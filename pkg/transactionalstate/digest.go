// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package transactionalstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// Digest is safe one-server-loss probe material. It contains no document
// content or deployment identity.
type Digest struct {
	Revision       int64
	DataSHA256     string
	ValidatedBytes int64
}

// Digest reads and hashes the same canonical complete document returned by
// Load. Callers may publish only this safe result, never Value.
func (store *Store) Digest(ctx context.Context, scope, key string) (Digest, error) {
	document, err := store.Load(ctx, scope, key)
	if err != nil {
		return Digest{}, err
	}
	sum := sha256.Sum256(document.Value)
	return Digest{
		Revision:       document.Revision,
		DataSHA256:     hex.EncodeToString(sum[:]),
		ValidatedBytes: int64(len(document.Value)),
	}, nil
}
