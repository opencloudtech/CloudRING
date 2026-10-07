// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package velero118

import (
	"context"
	"errors"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
)

type flakyReadMethod struct {
	failures int
	calls    int
}

func (method *flakyReadMethod) run() error {
	method.calls++
	if method.calls <= method.failures {
		return errors.New("transient Kubernetes API failure")
	}
	return nil
}

type flakyKubernetesReader struct {
	get, list, absent flakyReadMethod
}

func (reader *flakyKubernetesReader) Get(context.Context, restoreproof.GVR, string, string) ([]byte, error) {
	if err := reader.get.run(); err != nil {
		return nil, err
	}
	return []byte(`{"ok":true}`), nil
}

func (reader *flakyKubernetesReader) ListPage(context.Context, restoreproof.GVR, string, string, string, int) ([]byte, error) {
	if err := reader.list.run(); err != nil {
		return nil, err
	}
	return []byte(`{"items":[]}`), nil
}

func (reader *flakyKubernetesReader) ConfirmAbsent(context.Context, restoreproof.GVR, string, string) (bool, error) {
	if err := reader.absent.run(); err != nil {
		return false, err
	}
	return true, nil
}

func TestRetryingKubernetesReaderRecoversEveryIdempotentRead(t *testing.T) {
	t.Parallel()
	underlying := &flakyKubernetesReader{
		get:    flakyReadMethod{failures: 1},
		list:   flakyReadMethod{failures: 1},
		absent: flakyReadMethod{failures: 1},
	}
	clock := &fakeClock{}
	reader := withReadRetries(underlying, clock)
	if _, err := reader.Get(t.Context(), restoreproof.CoreV1PVCGVR, "source", "volume"); err != nil {
		t.Fatalf("Get did not recover: %v", err)
	}
	if _, err := reader.ListPage(t.Context(), restoreproof.CoreV1PVCGVR, "source", "", "", 1); err != nil {
		t.Fatalf("ListPage did not recover: %v", err)
	}
	if absent, err := reader.ConfirmAbsent(t.Context(), restoreproof.CoreV1PVCGVR, "source", "volume"); err != nil || !absent {
		t.Fatalf("ConfirmAbsent did not recover: absent=%t err=%v", absent, err)
	}
	if underlying.get.calls != 2 || underlying.list.calls != 2 || underlying.absent.calls != 2 || clock.waits != 3 {
		t.Fatalf("retry calls get/list/absent=%d/%d/%d waits=%d", underlying.get.calls, underlying.list.calls, underlying.absent.calls, clock.waits)
	}
}

func TestRetryingKubernetesReaderIsBoundedAndDoesNotRetryNotFound(t *testing.T) {
	t.Parallel()
	underlying := &flakyKubernetesReader{get: flakyReadMethod{failures: readRetryAttempts + 1}}
	clock := &fakeClock{}
	reader := withReadRetries(underlying, clock)
	if _, err := reader.Get(t.Context(), restoreproof.CoreV1PVCGVR, "source", "volume"); err == nil {
		t.Fatal("persistent API failure unexpectedly passed")
	}
	if underlying.get.calls != readRetryAttempts || clock.waits != readRetryAttempts-1 {
		t.Fatalf("retry bound calls=%d waits=%d", underlying.get.calls, clock.waits)
	}

	notFound := &notFoundReader{}
	reader = withReadRetries(notFound, &fakeClock{})
	if _, err := reader.Get(t.Context(), restoreproof.CoreV1PVCGVR, "source", "volume"); !errors.Is(err, ErrNotFound) || notFound.calls != 1 {
		t.Fatalf("not-found retry result calls=%d err=%v", notFound.calls, err)
	}
}

type notFoundReader struct{ calls int }

func (reader *notFoundReader) Get(context.Context, restoreproof.GVR, string, string) ([]byte, error) {
	reader.calls++
	return nil, ErrNotFound
}
func (*notFoundReader) ListPage(context.Context, restoreproof.GVR, string, string, string, int) ([]byte, error) {
	return nil, errors.New("unused")
}
func (*notFoundReader) ConfirmAbsent(context.Context, restoreproof.GVR, string, string) (bool, error) {
	return false, errors.New("unused")
}
