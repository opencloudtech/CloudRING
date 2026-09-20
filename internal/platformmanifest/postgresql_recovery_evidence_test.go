// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package platformmanifest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyPostgreSQLRecoveryEvidenceDelegatesToPublicContract(t *testing.T) {
	if err := VerifyPostgreSQLRecoveryEvidence(bytes.NewBufferString(`{}`)); err == nil {
		t.Fatal("invalid recovery evidence was accepted")
	}
	payload, err := os.ReadFile(filepath.Join(repositoryRoot(t), "pkg", "backup", "cnpgrecovery", "testdata", "synthetic-v2-evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPostgreSQLRecoveryEvidence(bytes.NewReader(payload)) != nil || VerifyPostgreSQLRecoveryEvidenceForRevision(bytes.NewReader(payload), strings.Repeat("a", 40)) != nil {
		t.Fatal("complete v2 fixture was rejected by the platform wrapper")
	}
	if VerifyPostgreSQLRecoveryEvidenceForRevision(bytes.NewReader(payload), strings.Repeat("b", 40)) == nil {
		t.Fatal("platform wrapper accepted a different source revision")
	}
	var fixture map[string]any
	if json.Unmarshal(payload, &fixture) != nil {
		t.Fatal("decode synthetic evidence fixture")
	}
	fixture["schemaVersion"] = "cloudring.postgresql-cnpg-offcell-recovery-evidence/v1"
	for _, field := range []string{"consistency", "recoveryAccess", "catalog", "application", "classes"} {
		delete(fixture, field)
	}
	legacy, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPostgreSQLRecoveryEvidence(bytes.NewReader(legacy)) == nil {
		t.Fatal("historical v1 fixture satisfied the v2 platform contract")
	}
}

func TestPostgreSQLRecoverySchemaRejectsAssuranceWeakening(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(repositoryRoot(t), postgresqlHARecoveryEvidencePath))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(map[string]any){
		"v1": func(s map[string]any) {
			nested(s, "properties", "schemaVersion").(map[string]any)["const"] = "cloudring.postgresql-cnpg-offcell-recovery-evidence/v1"
		},
		"missing-root-assurance": func(s map[string]any) { delete(s["properties"].(map[string]any), "consistency") },
		"optional-qualification": func(s map[string]any) {
			nested(s, "$defs", "consistency").(map[string]any)["required"] = []string{"method"}
		},
		"assigned-observer-xid": func(s map[string]any) {
			nested(s, "$defs", "consistency", "properties", "snapshotXidAssigned").(map[string]any)["const"] = true
		},
		"optional-commit": func(s map[string]any) {
			delete(nested(s, "$defs", "consistency", "properties", "markerCommitConfirmed").(map[string]any), "const")
		},
		"false-archive": func(s map[string]any) {
			nested(s, "$defs", "consistency", "properties", "exactMarkerArchived").(map[string]any)["const"] = false
		},
		"unverified-read-policy": func(s map[string]any) {
			nested(s, "$defs", "recoveryAccess", "properties", "independentPolicyVerified").(map[string]any)["const"] = false
		},
		"missing-policy-version": func(s map[string]any) {
			delete(nested(s, "$defs", "recoveryAccessBinding", "properties").(map[string]any), "policyRevisionIdentity")
		},
		"optional-app-authentication": func(s map[string]any) {
			nested(s, "$defs", "application").(map[string]any)["required"] = []string{"principalIdentity"}
		},
		"any-denial-error": func(s map[string]any) {
			nested(s, "$defs", "applicationDeny", "properties", "sqlState").(map[string]any)["const"] = "25P02"
		},
		"unverified-catalog": func(s map[string]any) {
			nested(s, "$defs", "catalog", "properties", "sourceContractValid").(map[string]any)["const"] = false
		},
		"partial-class-set": func(s map[string]any) { nested(s, "properties", "classes").(map[string]any)["minItems"] = 4 },
		"substituted-class": func(s map[string]any) {
			items := nested(s, "properties", "classes", "prefixItems").([]any)
			items[0] = items[1]
		},
		"raw-identity": func(s map[string]any) { delete(nested(s, "$defs", "digest").(map[string]any), "pattern") },
		"legacy-cleanup-residue": func(s map[string]any) {
			nested(s, "$defs", "cleanupSweep", "properties", "persistentVolumeClaimCount").(map[string]any)["const"] = 1
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			var schema map[string]any
			if json.Unmarshal(payload, &schema) != nil {
				t.Fatal("decode source schema")
			}
			change(schema)
			changed, err := json.Marshal(schema)
			if err != nil {
				t.Fatal(err)
			}
			if validatePostgreSQLHARecoveryEvidenceSchema(changed) == nil {
				t.Fatal("weakened v2 source schema was accepted")
			}
		})
	}
}
