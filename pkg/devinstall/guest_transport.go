// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

const plainStreamProtocol = "plain.kubevirt.io"

var errGuestAuthentication = errors.New("owned guest SSH authentication failed")

type guestClient struct {
	ssh  *ssh.Client
	stop func() bool
}

// KubeVirt v1.8.4 exposes portforward as a plain binary WebSocket byte stream:
// staging/src/kubevirt.io/client-go/kubecli/{async,streamer,websocket}.go.
// TLS authenticates the selected API server; an independent generated host
// key authenticates the owned guest reached through that server.
func (client *Client) connectGuest(ctx context.Context, state State) (*guestClient, error) {
	if state.ProfileSHA256 != Fingerprint(client.profile) || state.InstallationID != client.profile.InstallationID {
		return nil, ErrConflict
	}
	key, err := ssh.ParsePrivateKey([]byte(state.Credentials.SSHClientPrivateKey))
	if err != nil {
		return nil, ErrCredentials
	}
	host, _, options, remaining, err := ssh.ParseAuthorizedKey([]byte(state.Credentials.SSHHostPublicKey))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(remaining)) != 0 {
		return nil, ErrCredentials
	}
	headers := http.Header{"User-Agent": {"cloudring-development/1"}}
	if client.bearer != "" {
		headers.Set("Authorization", "Bearer "+client.bearer)
	}
	location := "wss://" + strings.TrimPrefix(strings.TrimSuffix(client.profile.Target.APIServer, "/"), "https://") +
		"/apis/subresources.kubevirt.io/v1/namespaces/" + client.profile.Target.Namespace +
		"/virtualmachineinstances/" + client.profile.Target.VirtualMachine + "/portforward/22/tcp"
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	socket, response, err := websocket.Dial(dialCtx, location, &websocket.DialOptions{
		HTTPClient: client.http, HTTPHeader: headers, Subprotocols: []string{plainStreamProtocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("owned guest port-forward is unavailable")
	}
	if socket.Subprotocol() != plainStreamProtocol {
		_ = socket.CloseNow()
		return nil, errors.New("owned guest stream protocol mismatch")
	}
	connection := websocket.NetConn(ctx, socket, websocket.MessageBinary)
	socket.SetReadLimit(1 << 20) // NetConn resets this limit; set it afterwards.
	if connection.SetDeadline(time.Now().Add(20*time.Second)) != nil {
		_ = socket.CloseNow()
		return nil, errors.New("bound guest SSH handshake")
	}
	algorithms := ssh.SupportedAlgorithms()
	hostAlgorithms := []string{host.Type()}
	if host.Type() == ssh.KeyAlgoRSA {
		hostAlgorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	config := &ssh.ClientConfig{User: "cloudring", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(host), HostKeyAlgorithms: hostAlgorithms,
		Config: ssh.Config{KeyExchanges: algorithms.KeyExchanges, Ciphers: algorithms.Ciphers, MACs: algorithms.MACs}}
	sshConnection, channels, requests, err := ssh.NewClientConn(connection, "owned-cloudring-development-guest:22", config)
	if err != nil {
		_ = socket.CloseNow()
		return nil, errGuestAuthentication
	}
	if connection.SetDeadline(time.Time{}) != nil {
		_ = sshConnection.Close()
		return nil, errors.New("reset owned guest SSH deadline")
	}
	guest := &guestClient{ssh: ssh.NewClient(sshConnection, channels, requests)}
	guest.stop = context.AfterFunc(ctx, func() { _ = guest.ssh.Close() })
	return guest, nil
}

func (guest *guestClient) Close() error {
	if guest == nil || guest.ssh == nil {
		return nil
	}
	if guest.stop != nil {
		guest.stop()
	}
	return guest.ssh.Close()
}

// runFixed sends payloads only on SSH stdin. The caller selects a compile-time
// command; no profile, credential, endpoint or user string is shell-expanded.
func (guest *guestClient) runFixed(ctx context.Context, command string, input io.Reader) ([]byte, error) {
	session, err := guest.ssh.NewSession()
	if err != nil {
		return nil, errors.New("create owned guest SSH session")
	}
	defer session.Close()
	stop := context.AfterFunc(ctx, func() { _ = guest.ssh.Close() })
	defer stop()
	output := &boundedOutput{maximum: 64 << 10, cancel: func() { _ = guest.ssh.Close() }}
	stderr := &boundedOutput{maximum: 64 << 10, discard: true, cancel: func() { _ = guest.ssh.Close() }}
	session.Stdin, session.Stdout, session.Stderr = input, output, stderr
	err = session.Run(command)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || output.overflow || stderr.overflow || stderr.count != 0 {
		clear(output.buffer.Bytes())
		return nil, errors.New("owned guest operation failed")
	}
	return bytes.Clone(output.buffer.Bytes()), nil
}

type boundedOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	maximum  int
	count    int
	overflow bool
	discard  bool
	cancel   func()
}

func (output *boundedOutput) Write(payload []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	if len(payload) > output.maximum-output.count {
		output.overflow = true
		if output.cancel != nil {
			output.cancel()
		}
		return 0, errors.New("owned guest output exceeds bound")
	}
	output.count += len(payload)
	if output.discard {
		return len(payload), nil
	}
	return output.buffer.Write(payload)
}

// dialProvider is the only forwarded guest destination offered to local API
// clients. It does not expose a general-purpose SOCKS or arbitrary TCP proxy.
func (guest *guestClient) dialProvider(ctx context.Context, _, _ string) (net.Conn, error) {
	connection, err := guest.ssh.DialContext(ctx, "tcp", net.JoinHostPort(guestLoopback(), "30443"))
	if err != nil {
		return nil, errors.New("owned provider HTTPS port is unavailable")
	}
	return connection, nil
}

var _ io.Writer = (*boundedOutput)(nil)
