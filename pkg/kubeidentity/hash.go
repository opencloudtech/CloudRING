// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

// Package kubeidentity defines canonical privacy-safe hashes for Kubernetes
// object identities shared by public collectors and downstream adapters.
package kubeidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"unicode/utf8"
)

const (
	// NodeUIDHashAlgorithm identifies the exact Node UID hashing contract:
	// SHA-256(UTF-8(NodeUIDHashAlgorithm) || 0x00 || exact UTF-8 UID bytes).
	// The UID is not JSON-encoded, trimmed, normalized, or case-folded.
	NodeUIDHashAlgorithm = "cloudring.kubernetes.node-uid-sha256/v1"

	maximumNodeUIDBytes = 256
)

// NodeUIDSHA256 returns the canonical privacy-safe lowercase SHA-256 binding
// for one raw Kubernetes Node metadata.uid. Empty, invalid UTF-8, or unbounded
// input is rejected with an empty result.
func NodeUIDSHA256(uid string) string {
	if uid == "" || len(uid) > maximumNodeUIDBytes || !utf8.ValidString(uid) {
		return ""
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(NodeUIDHashAlgorithm))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(uid))
	return hex.EncodeToString(hash.Sum(nil))
}
