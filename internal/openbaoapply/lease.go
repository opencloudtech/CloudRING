// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package openbaoapply

import (
	"context"
	"errors"
	"sync"
	"time"
)

var errLeaseUnavailable = errors.New("exclusive operator lease unavailable")

const (
	leaseDurationSeconds int32 = 30
)

var leaseRenewInterval = 5 * time.Second

// leaseGuard cancels the operation on the first renewal failure. It never
// automatically takes over a non-empty holder, even if timestamps look stale.
type leaseGuard struct {
	client KubernetesClient
	target LeaseTarget

	operationCtx    context.Context
	operationCancel context.CancelFunc
	cleanupCtx      context.Context
	cleanupCancel   context.CancelFunc
	stop            chan struct{}
	done            chan struct{}

	mu      sync.Mutex
	current Lease
	lost    bool
}

func acquireLease(ctx context.Context, client KubernetesClient, target LeaseTarget) (*leaseGuard, bool, error) {
	current, err := client.GetLease(ctx, target)
	if err != nil || current.HolderIdentity != "" {
		return nil, false, errLeaseUnavailable
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	current.HolderIdentity = target.HolderIdentity
	current.LeaseDurationSec = leaseDurationSeconds
	current.AcquireTime = now
	current.RenewTime = now
	updated, err := client.UpdateLease(ctx, target, current)
	if err != nil || !exactLeaseUpdate(current, updated) {
		mutationAmbiguous := !definitelyRejected(err)
		if err == nil {
			mutationAmbiguous = true
		}
		return nil, mutationAmbiguous, errLeaseUnavailable
	}
	operationCtx, operationCancel := context.WithCancel(ctx)
	cleanupCtx, cleanupCancel := context.WithCancel(context.WithoutCancel(ctx))
	guard := &leaseGuard{
		client: client, target: target,
		operationCtx: operationCtx, operationCancel: operationCancel,
		cleanupCtx: cleanupCtx, cleanupCancel: cleanupCancel,
		stop: make(chan struct{}), done: make(chan struct{}), current: updated,
	}
	go guard.renew()
	return guard, true, nil
}

func (guard *leaseGuard) Context() context.Context { return guard.operationCtx }

func (guard *leaseGuard) CleanupContext() context.Context { return guard.cleanupCtx }

func (guard *leaseGuard) renew() {
	defer close(guard.done)
	ticker := time.NewTicker(leaseRenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-guard.stop:
			return
		case <-guard.cleanupCtx.Done():
			return
		case now := <-ticker.C:
			guard.mu.Lock()
			current := guard.current
			guard.mu.Unlock()
			current.RenewTime = now.UTC().Truncate(time.Microsecond)
			updated, err := guard.client.UpdateLease(guard.cleanupCtx, guard.target, current)
			if err != nil || !exactLeaseUpdate(current, updated) {
				guard.mu.Lock()
				guard.lost = true
				guard.mu.Unlock()
				guard.operationCancel()
				guard.cleanupCancel()
				return
			}
			guard.mu.Lock()
			guard.current = updated
			guard.mu.Unlock()
		}
	}
}

func (guard *leaseGuard) release(ctx context.Context) error {
	select {
	case <-guard.stop:
	default:
		close(guard.stop)
	}
	<-guard.done
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.lost || guard.current.HolderIdentity != guard.target.HolderIdentity {
		guard.operationCancel()
		guard.cleanupCancel()
		return errLeaseUnavailable
	}
	current := guard.current
	current.HolderIdentity = ""
	current.RenewTime = time.Now().UTC().Truncate(time.Microsecond)
	updated, err := guard.client.UpdateLease(ctx, guard.target, current)
	guard.operationCancel()
	guard.cleanupCancel()
	if err != nil || !exactLeaseUpdate(current, updated) {
		return errLeaseUnavailable
	}
	postState, err := guard.client.GetLease(ctx, guard.target)
	if err != nil || postState.UID != updated.UID || postState.ResourceVersion != updated.ResourceVersion || postState.HolderIdentity != "" {
		return errLeaseUnavailable
	}
	return nil
}

func exactLeaseUpdate(requested, updated Lease) bool {
	return updated.Name == requested.Name && updated.Namespace == requested.Namespace && updated.UID == requested.UID && updated.ResourceVersion != "" && updated.ResourceVersion != requested.ResourceVersion &&
		updated.HolderIdentity == requested.HolderIdentity && updated.LeaseDurationSec == requested.LeaseDurationSec &&
		updated.AcquireTime.Equal(requested.AcquireTime) && updated.RenewTime.Equal(requested.RenewTime)
}

func (guard *leaseGuard) abandon() {
	select {
	case <-guard.stop:
	default:
		close(guard.stop)
	}
	<-guard.done
	guard.operationCancel()
	guard.cleanupCancel()
}

func (guard *leaseGuard) healthy() bool {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return !guard.lost && guard.cleanupCtx.Err() == nil
}
