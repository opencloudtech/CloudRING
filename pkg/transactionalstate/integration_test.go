// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package transactionalstate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgreSQLDocumentLifecycleAndConcurrency(t *testing.T) {
	dsn := os.Getenv("CLOUDRING_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDRING_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("connect isolated PostgreSQL integration database")
	}
	defer admin.Close()
	var ownerRole, databaseOwner string
	if err := admin.QueryRow(ctx, `
		SELECT current_user, pg_get_userbyid(datdba)
		FROM pg_database
		WHERE datname = current_database()
	`).Scan(&ownerRole, &databaseOwner); err != nil || ownerRole != databaseOwner {
		t.Fatal("integration database user is not its database owner")
	}
	applicationRole := "cloudring_app_integration"
	applicationIdentifier := pgx.Identifier{applicationRole}.Sanitize()
	if _, err := admin.Exec(ctx, `DROP SCHEMA IF EXISTS cloudring_state CASCADE`); err != nil {
		t.Fatal("reset isolated integration schema")
	}
	if _, err := admin.Exec(ctx, `DROP ROLE IF EXISTS `+applicationIdentifier); err != nil {
		t.Fatal("reset isolated integration role")
	}
	if _, err := admin.Exec(ctx, `CREATE ROLE `+applicationIdentifier+` LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal("create least-privileged integration role")
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA IF EXISTS cloudring_state CASCADE`)
		_, _ = admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+applicationIdentifier)
	}()

	migrationConfig := Config{
		DSN:                   dsn,
		ApplicationName:       "cloudring-integration-migrate",
		MigrationOwnerRole:    ownerRole,
		ApplicationRole:       applicationRole,
		AllowInsecureForTests: true,
	}
	if err := Migrate(ctx, migrationConfig); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, migrationConfig); err != nil {
		t.Fatalf("idempotent migration failed: %v", err)
	}
	applicationConfig := Config{
		DSN:                   testDSNForRole(t, dsn, applicationRole),
		ApplicationName:       "cloudring-integration-app",
		AllowInsecureForTests: true,
	}
	store, err := Open(ctx, applicationConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	scope := "integration"
	key := "document-lifecycle"
	created, err := store.Save(ctx, scope, key, 0, []byte(`{"counter":0,"tenant":"synthetic"}`))
	if err != nil || created.Revision != 1 {
		t.Fatalf("create = %#v, %v", created, err)
	}
	if _, err := store.Save(ctx, scope, key, 0, []byte(`{"counter":1}`)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate create = %v, want conflict", err)
	}

	const writers = 12
	var successes atomic.Int32
	var wait sync.WaitGroup
	for index := range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.Save(ctx, scope, key, created.Revision, []byte(`{"counter":1,"tenant":"synthetic"}`))
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrConflict):
			default:
				t.Errorf("writer %d: %v", index, err)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful concurrent writers = %d, want 1", successes.Load())
	}
	loaded, err := store.Load(ctx, scope, key)
	if err != nil || loaded.Revision != 2 {
		t.Fatalf("load = %#v, %v", loaded, err)
	}
	digest, err := store.Digest(ctx, scope, key)
	if err != nil || digest.Revision != loaded.Revision || digest.ValidatedBytes != int64(len(loaded.Value)) || len(digest.DataSHA256) != 64 {
		t.Fatalf("digest = %#v, %v", digest, err)
	}
	if err := store.Delete(ctx, scope, key, loaded.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, scope, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("load after delete = %v, want not found", err)
	}
	if _, err := store.pool.Exec(ctx, `CREATE TABLE cloudring_state.forbidden_ddl (value text)`); err == nil {
		t.Fatal("application role received schema DDL privileges")
	}
	testPostgreSQLAuditJournal(t, ctx, store)

	if _, err := admin.Exec(ctx, `ALTER TABLE cloudring_state.documents ADD COLUMN unexpected_column text`); err != nil {
		t.Fatal("inject isolated catalog drift")
	}
	if err := Migrate(ctx, migrationConfig); err == nil {
		t.Fatal("migration accepted catalog drift with a valid checksum")
	}
	if _, err := admin.Exec(ctx, `ALTER TABLE cloudring_state.documents DROP COLUMN unexpected_column`); err != nil {
		t.Fatal("remove isolated catalog drift")
	}
	if _, err := admin.Exec(ctx, `ALTER TABLE cloudring_state.documents ADD CONSTRAINT unexpected_unique UNIQUE (scope)`); err != nil {
		t.Fatal("inject isolated constraint drift")
	}
	if err := Migrate(ctx, migrationConfig); err == nil {
		t.Fatal("migration accepted an unexpected semantic constraint")
	}
	if _, err := admin.Exec(ctx, `ALTER TABLE cloudring_state.documents DROP CONSTRAINT unexpected_unique`); err != nil {
		t.Fatal("remove isolated constraint drift")
	}
	if _, err := admin.Exec(ctx, `UPDATE cloudring_state.schema_migrations SET checksum = repeat('0', 64) WHERE version = 1`); err != nil {
		t.Fatal("inject isolated checksum drift")
	}
	if err := Migrate(ctx, migrationConfig); err == nil {
		t.Fatal("migration checksum drift was accepted")
	}

	if _, err := admin.Exec(ctx, `DROP SCHEMA cloudring_state CASCADE`); err != nil {
		t.Fatal("reset schema for additive migration test")
	}
	for _, statement := range renderedMigrationOne(ownerRole, applicationRole) {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal("create version-one integration schema")
		}
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO cloudring_state.schema_migrations (version, checksum)
		VALUES (1, $1)
	`, migrationOneChecksum()); err != nil {
		t.Fatal("record version-one integration schema")
	}
	if err := Migrate(ctx, migrationConfig); err != nil {
		t.Fatalf("additive audit journal migration failed: %v", err)
	}
	var journalCreated bool
	if err := admin.QueryRow(ctx, `SELECT to_regclass('cloudring_state.audit_journal') IS NOT NULL`).Scan(&journalCreated); err != nil || !journalCreated {
		t.Fatal("additive migration did not create the audit journal")
	}

	if _, err := admin.Exec(ctx, `DROP SCHEMA cloudring_state CASCADE`); err != nil {
		t.Fatal("reset schema for pre-existing-object test")
	}
	ownerIdentifier := pgx.Identifier{ownerRole}.Sanitize()
	if _, err := admin.Exec(ctx, `CREATE SCHEMA cloudring_state AUTHORIZATION `+ownerIdentifier+`; CREATE TABLE cloudring_state.documents (wrong_shape text)`); err != nil {
		t.Fatal("create isolated conflicting schema")
	}
	if err := Migrate(ctx, migrationConfig); err == nil {
		t.Fatal("migration blessed a pre-existing conflicting schema")
	}
	var historyCreated bool
	if err := admin.QueryRow(ctx, `SELECT to_regclass('cloudring_state.schema_migrations') IS NOT NULL`).Scan(&historyCreated); err != nil || historyCreated {
		t.Fatal("failed migration recorded history for a conflicting schema")
	}
}

func testPostgreSQLAuditJournal(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	scope := "tenant-a"
	original, err := store.AppendAuditEvent(ctx, scope, "event-02", []byte(`{"amount":1e2,"actor":"portal"}`))
	if err != nil || original.Scope != scope || original.ID != "event-02" || original.CreatedAt.IsZero() {
		t.Fatalf("append audit event = %#v, %v", original, err)
	}
	retried, err := store.AppendAuditEvent(ctx, scope, "event-02", []byte(` {"actor":"portal", "amount":1e2} `))
	if err != nil || !retried.CreatedAt.Equal(original.CreatedAt) || string(retried.Value) != string(original.Value) {
		t.Fatalf("idempotent audit append = %#v, %v, want %#v", retried, err, original)
	}
	if _, err := store.AppendAuditEvent(ctx, scope, "event-02", []byte(`{"actor":"different"}`)); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting audit append = %v, want conflict", err)
	}
	for _, fixture := range []struct {
		id    string
		value string
	}{
		{id: "event-01", value: `{"order":1}`},
		{id: "event-03", value: `{"order":3}`},
	} {
		if _, err := store.AppendAuditEvent(ctx, scope, fixture.id, []byte(fixture.value)); err != nil {
			t.Fatalf("append ordered audit fixture %s: %v", fixture.id, err)
		}
	}
	otherScope, err := store.AppendAuditEvent(ctx, "tenant-b", "event-02", []byte(`{"tenant":"b"}`))
	if err != nil || string(otherScope.Value) != `{"tenant":"b"}` {
		t.Fatalf("append isolated audit event = %#v, %v", otherScope, err)
	}

	firstPage, err := store.ListAuditEvents(ctx, scope, "", 2)
	if err != nil || len(firstPage.Events) != 2 || firstPage.Events[0].ID != "event-01" || firstPage.Events[1].ID != "event-02" || firstPage.NextAfterID != "event-02" {
		t.Fatalf("first audit page = %#v, %v", firstPage, err)
	}
	secondPage, err := store.ListAuditEvents(ctx, scope, firstPage.NextAfterID, 2)
	if err != nil || len(secondPage.Events) != 1 || secondPage.Events[0].ID != "event-03" || secondPage.NextAfterID != "" {
		t.Fatalf("second audit page = %#v, %v", secondPage, err)
	}
	isolatedPage, err := store.ListAuditEvents(ctx, "tenant-b", "", MaximumAuditPageSize)
	if err != nil || len(isolatedPage.Events) != 1 || isolatedPage.Events[0].ID != "event-02" || string(isolatedPage.Events[0].Value) != `{"tenant":"b"}` {
		t.Fatalf("isolated audit page = %#v, %v", isolatedPage, err)
	}
	loaded, err := store.ReadAuditEvent(ctx, scope, "event-02")
	if err != nil || loaded.ID != original.ID || string(loaded.Value) != string(original.Value) {
		t.Fatalf("read audit event = %#v, %v", loaded, err)
	}
	if _, err := store.ReadAuditEvent(ctx, "tenant-c", "event-02"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-scope audit read = %v, want not found", err)
	}
	if _, err := store.ListAuditEvents(ctx, scope, "", MaximumAuditPageSize+1); err == nil {
		t.Fatal("audit list accepted an oversized page")
	}
	if _, err := store.AppendAuditEvent(ctx, scope, "event-oversized", bytes.Repeat([]byte(" "), MaximumAuditEventBytes+1)); err == nil {
		t.Fatal("audit append accepted an oversized event")
	}

	const retries = 12
	var wait sync.WaitGroup
	var failures atomic.Int32
	for range retries {
		wait.Add(1)
		go func() {
			defer wait.Done()
			event, err := store.AppendAuditEvent(ctx, scope, "event-concurrent", []byte(`{"retry":true}`))
			if err != nil || event.ID != "event-concurrent" {
				failures.Add(1)
			}
		}()
	}
	wait.Wait()
	if failures.Load() != 0 {
		t.Fatalf("concurrent idempotent audit append failures = %d", failures.Load())
	}

	for name, statement := range map[string]string{
		"update":   `UPDATE cloudring_state.audit_journal SET body = '{"mutated":true}' WHERE scope = 'tenant-a'`,
		"delete":   `DELETE FROM cloudring_state.audit_journal WHERE scope = 'tenant-a'`,
		"truncate": `TRUNCATE cloudring_state.audit_journal`,
	} {
		if _, err := store.pool.Exec(ctx, statement); err == nil {
			t.Fatalf("application role received audit journal %s privilege", name)
		}
	}
}

func testDSNForRole(t *testing.T, dsn, role string) string {
	t.Helper()
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse isolated integration database configuration")
	}
	quote := func(value string) string {
		value = strings.ReplaceAll(value, `\`, `\\`)
		value = strings.ReplaceAll(value, `'`, `\'`)
		return `'` + value + `'`
	}
	return fmt.Sprintf("host=%s port=%d dbname=%s user=%s sslmode=disable",
		quote(parsed.Host), parsed.Port, quote(parsed.Database), quote(role))
}
