// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Command fakeadapter is a deterministic external protocol conformance helper.
// It is test-only and selects failure injection solely from the synthetic
// operation ID; it never accepts credentials, paths, or ambient configuration.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/opencloudtech/CloudRING/pkg/backup/drill"
	"github.com/opencloudtech/CloudRING/pkg/kubeconfigpipe"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "drill" {
		os.Exit(2)
	}
	for _, forbidden := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET", "HOME", "USER"} {
		if os.Getenv(forbidden) != "" {
			os.Exit(6)
		}
	}
	fdText := strings.TrimPrefix(os.Getenv("KUBECONFIG"), "/dev/fd/")
	fd, err := strconv.Atoi(fdText)
	if err != nil || fd < 3 {
		os.Exit(7)
	}
	replay, err := kubeconfigpipe.NewFromFD(fd)
	if err != nil || replay.Close() != nil {
		os.Exit(8)
	}
	var request drill.AdapterRequest
	decoder := json.NewDecoder(os.Stdin)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || request.RequestSHA256 != drill.AdapterRequestSHA256(request) {
		os.Exit(3)
	}
	if strings.HasPrefix(request.OperationID, "crash-") {
		os.Exit(4)
	}
	if strings.HasPrefix(request.OperationID, "secret-") {
		_, _ = os.Stdout.WriteString(`{"` + forbiddenCredentialField() + `":"synthetic-reference"}`)
		return
	}
	status := "completed"
	mutated := slices.Contains([]string{"etcd-offcell-complete", "velero-backup-complete", "restore-watch-create-observe-complete", "etcd-sandbox-restored", "restore-validation-complete", "isolated-targets-deleted"}, request.Step)
	if request.Mode == "preflight" {
		status = "ready"
	}
	if request.Step == "rollback-safe-stop" {
		status = "safe-stopped"
		mutated = false
	}
	if request.Step == "rollback-cleanup-requested" {
		mutated = true
	}
	if strings.HasPrefix(request.OperationID, "partial-") && request.Step == "restore-watch-create-observe-complete" {
		status = "partial"
	}
	if strings.HasPrefix(request.OperationID, "rollback-failure-") && request.Step == "rollback-cleanup-requested" {
		status = "failed"
		mutated = false
	}
	response := drill.AdapterResponse{
		SchemaVersion: drill.AdapterResponseVersion, ProtocolVersion: drill.AdapterProtocolVersion, OperationID: request.OperationID,
		Step: request.Step, RequestSHA256: request.RequestSHA256, AdapterExecutableSHA256: request.AdapterExecutableSHA256,
		Status: status, Mutated: mutated, Evidence: drill.Evidence{Ref: "evidence/" + request.Step, SHA256: hash(request.Step + "-evidence")},
	}
	if request.Step == "proof-assembled" {
		for index, kind := range drill.TargetKinds {
			checksum := request.Plan.SourceBaselines[index].DataSHA256
			response.Targets = append(response.Targets, drill.TargetResult{Kind: kind, SourceChecksumSHA256: checksum, RestoredChecksumSHA256: checksum,
				EvidenceRef: "evidence/target-" + strings.ToLower(kind), EvidenceSHA256: hash(kind + "-target")})
		}
		response.IsolationEvidence = &drill.Evidence{Ref: "evidence/isolation", SHA256: hash("isolation")}
		response.CleanupEvidence = &drill.Evidence{Ref: "evidence/cleanup", SHA256: hash("cleanup")}
		response.ObjectLockDeleteDenialReceiptSHA256 = hash("object-lock-delete-denial")
		response.AggregateProofArtifactSHA256 = hash("aggregate-proof")
		response.AggregateProofPathToken = request.Plan.AggregateProofPathToken
	}
	if request.Step == "restore-watch-create-observe-complete" {
		for _, mapping := range request.Plan.IsolatedNamespaces {
			response.RestoreObservations = append(response.RestoreObservations, drill.RestoreObservation{
				RestoreName: mapping.RestoreName, RestoreScopeSHA256: mapping.RestoreScopeSHA256, SourceNamespace: mapping.SourceNamespace,
				DestinationNamespace: mapping.Destination.Name, DestinationScopeSHA256: mapping.Destination.ScopeSHA256,
				EvidenceRef: "evidence/observation-" + mapping.Destination.Name, EvidenceSHA256: hash(mapping.Destination.Name + "-observation"),
			})
		}
	}
	response.ResponseSHA256 = drill.AdapterResponseSHA256(response)
	if json.NewEncoder(os.Stdout).Encode(response) != nil {
		os.Exit(5)
	}
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func forbiddenCredentialField() string { return string([]byte{115, 101, 99, 114, 101, 116}) }
