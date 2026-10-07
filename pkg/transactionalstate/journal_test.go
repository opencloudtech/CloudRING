// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package transactionalstate

import (
	"bytes"
	"strings"
	"testing"
)

func TestCanonicalAuditJSONIsStrictAndBounded(t *testing.T) {
	got, err := canonicalAuditJSON([]byte(` {"z":1e2,"a":"event"} `))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"a":"event","z":1e2}`)
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical audit JSON = %s, want %s", got, want)
	}
	if first, second := auditPayloadSHA256(got), auditPayloadSHA256(got); len(first) != 64 || first != second {
		t.Fatalf("audit payload digest is not stable: %q, %q", first, second)
	}

	invalid := [][]byte{
		nil,
		[]byte(`{"duplicate":1,"duplicate":2}`),
		[]byte(`{"valid":true} {"trailing":true}`),
		bytes.Repeat([]byte(" "), MaximumAuditEventBytes+1),
	}
	for _, value := range invalid {
		if _, err := canonicalAuditJSON(value); err == nil {
			t.Fatalf("canonicalAuditJSON accepted invalid input of length %d", len(value))
		}
	}
}

func TestAuditJournalMigrationIsAdditiveAndImmutable(t *testing.T) {
	if migrationVersion != 2 || len(migrationOneChecksum()) != 64 || len(migrationTwoChecksum()) != 64 || migrationOneChecksum() == migrationTwoChecksum() {
		t.Fatal("audit journal migration checksums or version are invalid")
	}
	owner, application, err := migrationRoles(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(renderedMigrationOne(owner, application)) == 0 {
		t.Fatal("document migration unexpectedly changed")
	}
	statements := strings.Join(renderedMigrationTwo(application), "\n")
	for _, required := range []string{
		"CREATE TABLE cloudring_state.audit_journal",
		"PRIMARY KEY (scope, event_id)",
		"GRANT SELECT, INSERT ON TABLE cloudring_state.audit_journal",
	} {
		if !strings.Contains(statements, required) {
			t.Fatalf("audit migration is missing %q", required)
		}
	}
	if strings.Contains(statements, "DROP ") || strings.Contains(statements, "GRANT UPDATE") || strings.Contains(statements, "GRANT DELETE") {
		t.Fatal("audit migration permits journal mutation or destructive rollback")
	}
	if len(expectedCatalogColumns(2)) <= len(expectedCatalogColumns(1)) || len(expectedCatalogConstraints(2)) <= len(expectedCatalogConstraints(1)) {
		t.Fatal("audit migration contract is not additive")
	}
}

func TestAuditJournalPublicBounds(t *testing.T) {
	if MaximumAuditEventBytes != 256*1024 {
		t.Fatalf("MaximumAuditEventBytes = %d", MaximumAuditEventBytes)
	}
	if MaximumAuditPageSize != 100 {
		t.Fatalf("MaximumAuditPageSize = %d", MaximumAuditPageSize)
	}
	for _, value := range []string{"tenant-a", "portal.audit:01", strings.Repeat("a", 128)} {
		if !safeKeyPattern.MatchString(value) {
			t.Fatalf("safe audit identifier rejected: %q", value)
		}
	}
	for _, value := range []string{"", "TENANT", "tenant/a", strings.Repeat("a", 129)} {
		if safeKeyPattern.MatchString(value) {
			t.Fatalf("unsafe audit identifier accepted: %q", value)
		}
	}
	if err := validateAuditList("tenant-a", "", 1); err != nil {
		t.Fatalf("valid first audit page rejected: %v", err)
	}
	if err := validateAuditList("tenant-a", "event-01", MaximumAuditPageSize); err != nil {
		t.Fatalf("valid continuation audit page rejected: %v", err)
	}
	for _, fixture := range []struct {
		scope, after string
		pageSize     int
	}{
		{scope: "tenant-a", pageSize: 0},
		{scope: "tenant-a", pageSize: MaximumAuditPageSize + 1},
		{scope: "tenant/a", pageSize: 1},
		{scope: "tenant-a", after: "bad cursor", pageSize: 1},
	} {
		if err := validateAuditList(fixture.scope, fixture.after, fixture.pageSize); err == nil {
			t.Fatalf("invalid audit page accepted: %#v", fixture)
		}
	}
}
