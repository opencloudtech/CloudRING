// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package velero118

import (
	"context"
	"errors"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
)

const (
	readRetryAttempts     = 3
	readRetryInitialDelay = 50 * time.Millisecond
	readRetryMaximumDelay = 200 * time.Millisecond
	readRetryDeadline     = 30 * time.Second
)

type retryingKubernetesReader struct {
	reader KubernetesReader
	clock  Clock
}

type retryingKubernetesWatchReader struct {
	*retryingKubernetesReader
	watcher KubernetesWatchReader
}

func withReadRetries(reader KubernetesReader, clock Clock) KubernetesReader {
	if _, ok := reader.(*retryingKubernetesReader); ok {
		return reader
	}
	if _, ok := reader.(*retryingKubernetesWatchReader); ok {
		return reader
	}
	return &retryingKubernetesReader{reader: reader, clock: clock}
}

func withWatchReadRetries(reader KubernetesWatchReader, clock Clock) KubernetesWatchReader {
	if wrapped, ok := reader.(*retryingKubernetesWatchReader); ok {
		return wrapped
	}
	return &retryingKubernetesWatchReader{
		retryingKubernetesReader: &retryingKubernetesReader{reader: reader, clock: clock},
		watcher:                  reader,
	}
}

func (reader *retryingKubernetesReader) Get(ctx context.Context, gvr restoreproof.GVR, namespace, name string) ([]byte, error) {
	return retryRead(ctx, reader.clock, func(attemptContext context.Context) ([]byte, error) {
		return reader.reader.Get(attemptContext, gvr, namespace, name)
	})
}

func (reader *retryingKubernetesReader) ListPage(ctx context.Context, gvr restoreproof.GVR, namespace, selector, continueToken string, limit int) ([]byte, error) {
	return retryRead(ctx, reader.clock, func(attemptContext context.Context) ([]byte, error) {
		return reader.reader.ListPage(attemptContext, gvr, namespace, selector, continueToken, limit)
	})
}

func (reader *retryingKubernetesReader) ConfirmAbsent(ctx context.Context, gvr restoreproof.GVR, namespace, name string) (bool, error) {
	return retryRead(ctx, reader.clock, func(attemptContext context.Context) (bool, error) {
		return reader.reader.ConfirmAbsent(attemptContext, gvr, namespace, name)
	})
}

// WatchPage is intentionally not retried. A watch retry without preserving the
// returned resourceVersion could create an observation gap; the caller owns
// exact watch continuation.
func (reader *retryingKubernetesWatchReader) WatchPage(ctx context.Context, gvr restoreproof.GVR, namespace, selector, resourceVersion string, timeoutSeconds int) ([]WatchEvent, string, error) {
	return reader.watcher.WatchPage(ctx, gvr, namespace, selector, resourceVersion, timeoutSeconds)
}

func retryRead[T any](ctx context.Context, clock Clock, operation func(context.Context) (T, error)) (T, error) {
	var zero T
	if clock == nil || operation == nil {
		return zero, errors.New("Kubernetes read retry dependency is missing")
	}
	retryContext, cancel := context.WithTimeout(ctx, readRetryDeadline)
	defer cancel()
	delay := readRetryInitialDelay
	var lastErr error
	for attempt := 1; attempt <= readRetryAttempts; attempt++ {
		value, err := operation(retryContext)
		if err == nil || errors.Is(err, ErrNotFound) {
			return value, err
		}
		lastErr = err
		if attempt == readRetryAttempts || retryContext.Err() != nil {
			break
		}
		if err := clock.Wait(retryContext, delay); err != nil {
			break
		}
		delay *= 2
		if delay > readRetryMaximumDelay {
			delay = readRetryMaximumDelay
		}
	}
	if retryContext.Err() != nil {
		return zero, retryContext.Err()
	}
	return zero, lastErr
}
