// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

// Package openbaoexecutor renders the temporary Kubernetes identities, Lease,
// and least-privilege RBAC required by the protected OpenBao bootstrap
// executor. It accepts no credentials, endpoints, certificates, or tokens.
package openbaoexecutor

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
)

const (
	SchemaVersion = "cloudring.openbao-kubernetes-auth-executor/v1"
	MaxInputBytes = 128 * 1024
)

// Profile binds one validated OpenBao workload contract to an ephemeral
// Kubernetes executor boundary. The positive workload identity and dedicated
// negative namespace are owned by the consumer installation and are
// deliberately not rendered by this package.
type Profile struct {
	SchemaVersion      string                       `json:"schemaVersion"`
	Contract           openbaoauth.Contract         `json:"contract"`
	ExecutorIdentity   openbaoauth.WorkloadIdentity `json:"executorIdentity"`
	Lease              LeaseTarget                  `json:"lease"`
	NegativeIdentities NegativeIdentities           `json:"negativeIdentities"`
}

// LeaseTarget names the pre-created, initially empty coordination Lease. Its
// name must equal ExecutorScopeName(executorIdentity), which safely scopes the
// cluster-wide RBAC to that Kubernetes identity.
type LeaseTarget struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// NegativeIdentities isolate the two Kubernetes-auth binding dimensions.
type NegativeIdentities struct {
	WrongServiceAccount openbaoauth.WorkloadIdentity `json:"wrongServiceAccount"`
	WrongNamespace      openbaoauth.WorkloadIdentity `json:"wrongNamespace"`
}

// Problem is a stable, value-free validation result safe for logs and tests.
type Problem struct {
	Path string `json:"path"`
	Code string `json:"code"`
}

// ExecutorScopeName returns the stable cluster-scoped object name for one
// executor identity. Length prefixes make the preimage unambiguous, while the
// versioned domain and 160-bit SHA-256 prefix keep the DNS label at 63 bytes.
func ExecutorScopeName(identity openbaoauth.WorkloadIdentity) string {
	input := make([]byte, 0, 64+len(identity.Namespace)+len(identity.ServiceAccount))
	input = append(input, "cloudring.openbao-executor-scope/v1\x00"...)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(identity.Namespace)))
	input = append(input, length[:]...)
	input = append(input, identity.Namespace...)
	binary.BigEndian.PutUint64(length[:], uint64(len(identity.ServiceAccount)))
	input = append(input, length[:]...)
	input = append(input, identity.ServiceAccount...)
	digest := sha256.Sum256(input)
	return "cloudring-openbao-exec-" + hex.EncodeToString(digest[:20])
}
