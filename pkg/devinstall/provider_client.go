// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ProviderObservation struct {
	InstallationID        string    `json:"installationID"`
	Profile               string    `json:"profile"`
	Status                string    `json:"status"`
	OperatorID            string    `json:"operatorID"`
	CreatedAt             time.Time `json:"createdAt"`
	ProductCount          int       `json:"productCount"`
	Database              string    `json:"database"`
	SourceRevision        string    `json:"sourceRevision"`
	SourceModified        bool      `json:"sourceModified"`
	UnauthenticatedDenied bool      `json:"unauthenticatedDenied"`
	ForeignTokenDenied    bool      `json:"foreignTokenDenied"`
}

func (engine *Engine) observeProvider(ctx context.Context, guest *guestClient) (ProviderObservation, error) {
	state := engine.Store.State
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(state.Credentials.CACertificate)) {
		return ProviderObservation{}, ErrCredentials
	}
	transport := &http.Transport{Proxy: nil, DialContext: guest.dialProvider,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: apiHostname(state.Profile)},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 64 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path, token string) (int, []byte, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, state.Profile.Network.PublicOrigin+path, nil)
		if err != nil {
			return 0, nil, ErrInvalidProfile
		}
		request.Header.Set("Accept", "application/json")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(request)
		if err != nil {
			return 0, nil, errors.New("verified provider HTTPS request failed")
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		if err != nil || len(payload) > 1<<20 {
			return 0, nil, errors.New("provider response exceeds bound")
		}
		return response.StatusCode, payload, nil
	}
	code, payload, err := get("/healthz/ready", "")
	clear(payload)
	if err != nil || code != http.StatusOK {
		return ProviderObservation{}, errors.New("owned provider database readiness is unverified")
	}
	code, payload, err = get("/api/v1/provider", state.Credentials.OperatorToken)
	defer clear(payload)
	if err != nil || code != http.StatusOK {
		return ProviderObservation{}, errors.New("owned provider authenticated readiness is unverified")
	}
	var status struct {
		APIVersion     string            `json:"apiVersion"`
		InstallationID string            `json:"installationID"`
		Profile        string            `json:"profile"`
		Status         string            `json:"status"`
		OperatorID     string            `json:"operatorID"`
		CreatedAt      time.Time         `json:"createdAt"`
		Products       []json.RawMessage `json:"products"`
		Components     struct {
			Database string `json:"database"`
		} `json:"components"`
		Build struct {
			SourceRevision string `json:"sourceRevision"`
			SourceModified bool   `json:"sourceModified"`
		} `json:"build"`
	}
	if json.Unmarshal(payload, &status) != nil || status.APIVersion != APIVersion || status.InstallationID != state.InstallationID || status.Profile != Development ||
		status.Status != "ready" || status.OperatorID != "dev-operator:"+state.InstallationID || status.CreatedAt.IsZero() || status.Products == nil ||
		status.Components.Database != "writable" || status.Build.SourceRevision != state.Profile.Artifacts.SourceCommit || status.Build.SourceModified {
		return ProviderObservation{}, errors.New("owned provider returned inconsistent identity, database or public build evidence")
	}
	deniedCredentials := []string{"", strings.Repeat("0", 64)}
	for _, candidate := range deniedCredentials {
		if candidate == state.Credentials.OperatorToken {
			return ProviderObservation{}, ErrCredentials
		}
		code, payload, err := get("/api/v1/provider", candidate)
		clear(payload)
		if err != nil || code != http.StatusUnauthorized {
			return ProviderObservation{}, errors.New("owned provider operator denial failed")
		}
	}
	return ProviderObservation{InstallationID: status.InstallationID, Profile: status.Profile, Status: status.Status, OperatorID: status.OperatorID,
		CreatedAt: status.CreatedAt, ProductCount: len(status.Products), Database: status.Components.Database, SourceRevision: status.Build.SourceRevision,
		SourceModified: status.Build.SourceModified, UnauthenticatedDenied: true, ForeignTokenDenied: true}, nil
}

func (engine *Engine) Status(ctx context.Context) (Report, error) {
	if err := engine.guard(); err != nil {
		return Report{}, err
	}
	report := engine.report()
	if err := engine.Client.verifyCluster(ctx); err != nil {
		return report, err
	}
	for _, owned := range engine.Store.State.Objects {
		observed, err := engine.Client.get(ctx, owned.Object)
		if err != nil {
			return report, err
		}
		if _, _, err := readOwned(observed, owned.Object, engine.Store.State); err != nil {
			return report, err
		}
	}
	if engine.Store.State.Phase != "ready" || !engine.Store.State.GuestBootstrapped {
		return report, errors.New("owned provider installation is incomplete")
	}
	if _, err := engine.verifyVMI(ctx); err != nil {
		return report, err
	}
	guest, err := engine.Client.connectGuest(ctx, engine.Store.State)
	if err != nil {
		return report, err
	}
	defer guest.Close()
	if err := engine.verifyGuestIdentity(ctx, guest); err != nil {
		return report, err
	}
	observation, err := engine.observeProvider(ctx, guest)
	if err != nil {
		return report, err
	}
	report.Ready = true
	report.Provider = &observation
	report.Checks = []Check{{Name: "owned-object-identities", Passed: true}, {Name: "verified-provider-api", Passed: true}, {Name: "operator-denials", Passed: true}}
	return report, nil
}

func (engine *Engine) Diagnose(ctx context.Context) (Report, error) {
	if err := engine.guard(); err != nil {
		return Report{}, err
	}
	report := engine.report()
	if err := engine.Client.verifyCluster(ctx); err != nil {
		report.Checks = append(report.Checks, Check{Name: "target-cluster", Code: "identity-or-access-failed"})
		return report, nil
	}
	report.Checks = append(report.Checks, Check{Name: "target-cluster", Passed: true})
	for _, owned := range engine.Store.State.Objects {
		check := Check{Name: "owned-" + owned.Kind}
		object, err := engine.Client.get(ctx, owned.Object)
		if apiStatus(err, http.StatusNotFound) {
			check.Code = "absent"
		} else if err != nil {
			check.Code = "access-failed"
		} else if _, _, err := readOwned(object, owned.Object, engine.Store.State); err != nil {
			check.Code = "ownership-conflict"
		} else {
			check.Passed = true
		}
		report.Checks = append(report.Checks, check)
	}
	actual, err := engine.Status(ctx)
	if err != nil {
		report.Checks = append(report.Checks, Check{Name: "actual-provider", Code: "not-ready"})
	} else {
		report.Ready = actual.Ready
		report.Provider = actual.Provider
		report.Checks = append(report.Checks, Check{Name: "actual-provider", Passed: true})
	}
	return report, nil
}

// Connect keeps a single loopback HTTPS forwarding listener in the foreground.
// It owns no background process, proxy configuration, DNS or global CA trust.
func (engine *Engine) Connect(ctx context.Context) error {
	if _, err := engine.Status(ctx); err != nil {
		return err
	}
	guest, err := engine.Client.connectGuest(ctx, engine.Store.State)
	if err != nil {
		return err
	}
	defer guest.Close()
	if err := engine.verifyGuestIdentity(ctx, guest); err != nil {
		return err
	}
	origin, _ := url.Parse(engine.Store.State.Profile.Network.PublicOrigin)
	listener, err := net.Listen("tcp4", net.JoinHostPort(guestLoopback(), origin.Port()))
	if err != nil {
		return errors.New("owned provider loopback port is already in use or unavailable")
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	go func() { _ = guest.ssh.Wait(); cancel() }()
	var active sync.WaitGroup
	defer func() { cancel(); _ = guest.Close(); active.Wait() }()
	semaphore := make(chan struct{}, 16)
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("owned provider loopback listener failed")
		}
		select {
		case semaphore <- struct{}{}:
		default:
			_ = connection.Close()
			continue
		}
		active.Add(1)
		go func() {
			defer active.Done()
			defer func() { <-semaphore }()
			defer connection.Close()
			stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
			defer stop()
			_ = connection.SetDeadline(time.Now().Add(5 * time.Minute))
			upstream, err := guest.dialProvider(ctx, "", "")
			if err != nil {
				return
			}
			defer upstream.Close()
			stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
			defer stopUpstream()
			done := make(chan struct{}, 1)
			go func() { _, _ = io.Copy(upstream, connection); _ = upstream.Close(); done <- struct{}{} }()
			_, _ = io.Copy(connection, upstream)
			_ = connection.Close()
			<-done
		}()
	}
}
