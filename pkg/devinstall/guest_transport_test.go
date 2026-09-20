// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

// This test exercises the actual TLS/WebSocket/SSH boundary on loopback. It
// does not claim a KubeVirt guest, PostgreSQL provider or installation exists.
func TestGuestStreamAuthenticatesTwoIndependentPeersAndBoundsCommands(t *testing.T) {
	profile := testProfile()
	credentials, err := newCredentials(profile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.ParsePrivateKey([]byte(credentials.SSHHostPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	clientKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(credentials.SSHClientPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), clientKey.Marshal()) {
			return nil, errors.New("unexpected client key")
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/apis/subresources.kubevirt.io/v1/namespaces/"+profile.Target.Namespace+"/virtualmachineinstances/"+profile.Target.VirtualMachine+"/portforward/22/tcp" || request.Header.Get("Authorization") != "Bearer "+testSubstrateBearer() {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{plainStreamProtocol}, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		raw := websocket.NetConn(request.Context(), connection, websocket.MessageBinary)
		server, channels, requests, err := ssh.NewServerConn(raw, config)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for channel := range channels {
			if channel.ChannelType() != "session" {
				_ = channel.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			accepted, requests, err := channel.Accept()
			if err != nil {
				return
			}
			go func() {
				defer accepted.Close()
				for request := range requests {
					if request.Type != "exec" {
						_ = request.Reply(false, nil)
						continue
					}
					var command struct{ Command string }
					if ssh.Unmarshal(request.Payload, &command) != nil {
						_ = request.Reply(false, nil)
						continue
					}
					_ = request.Reply(true, nil)
					payload, err := io.ReadAll(io.LimitReader(accepted, 4097))
					if err != nil || len(payload) > 4096 {
						return
					}
					switch command.Command {
					case "fixed-test-command":
						if string(payload) != "stdin-only-test-payload" {
							return
						}
						_, _ = accepted.Write([]byte("verified\n"))
					case "overflow-test-command":
						_, _ = accepted.Write(bytes.Repeat([]byte("x"), 65<<10))
					case "waiting-test-command":
						_, _ = io.Copy(io.Discard, accepted)
						return
					default:
						return
					}
					_, _ = accepted.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				}
			}()
		}
	})
	client, actualProfile, _ := testAPIClient(t, handler)
	state := State{InstallationID: actualProfile.InstallationID, Profile: actualProfile, ProfileSHA256: Fingerprint(actualProfile), Credentials: credentials}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	guest, err := client.connectGuest(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	output, err := guest.runFixed(ctx, "fixed-test-command", strings.NewReader("stdin-only-test-payload"))
	if err != nil || string(output) != "verified\n" {
		t.Fatalf("actual SSH stream failed after handshake: %q %v", output, err)
	}
	if _, err := guest.runFixed(ctx, "overflow-test-command", nil); err == nil {
		t.Fatal("unbounded SSH output accepted")
	}
	_ = guest.Close()
	otherPrivate, otherPublic, err := sshKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPrivate
	state.Credentials.SSHHostPublicKey = otherPublic
	if unexpected, err := client.connectGuest(ctx, state); err == nil {
		_ = unexpected.Close()
		t.Fatal("foreign guest host key accepted")
	}
}

func TestOwnedObjectFingerprintCannotAuthorizeAnotherIdentity(t *testing.T) {
	profile := testProfile()
	state := State{InstallationID: profile.InstallationID, Profile: profile, ProfileSHA256: Fingerprint(profile), OwnerNonce: strings.Repeat("a", 64)}
	ref := Object{APIVersion: "v1", Kind: "Namespace", Resource: "namespaces", Name: profile.Target.Namespace}
	object := apiObject{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ref.Name, "uid": "12345678-1234-4321-8123-123456789abc", "resourceVersion": "1",
		"labels": map[string]any{OwnerLabel: state.InstallationID}, "annotations": map[string]any{OwnerAnnotation: state.OwnerNonce, ProfileAnnotation: state.ProfileSHA256}}}
	owned, _, err := readOwned(object, ref, state)
	if err != nil {
		t.Fatal(err)
	}
	changed := ref
	changed.UID = "11111111-1111-4111-8111-111111111111"
	if _, _, err := readOwned(object, changed, state); !errors.Is(err, ErrConflict) {
		t.Fatal("replacement UID accepted")
	}
	meta, _ := metadata(object)
	nested(meta, "annotations")[OwnerAnnotation] = strings.Repeat("b", 64)
	if _, _, err := readOwned(object, owned.Object, state); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign installation owner accepted")
	}
	if !containsDesired(apiObject{"spec": map[string]any{"runStrategy": "Always", "defaulted": true}}, apiObject{"spec": map[string]any{"runStrategy": "Always"}}) ||
		containsDesired(apiObject{"spec": map[string]any{"runStrategy": "Manual"}}, apiObject{"spec": map[string]any{"runStrategy": "Always"}}) ||
		containsDesired([]any{"owned", "injected"}, []any{"owned"}) {
		t.Fatal("API defaulting accepted a changed ownership policy")
	}
}
