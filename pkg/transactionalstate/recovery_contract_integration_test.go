// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package transactionalstate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The dedicated variable prevents this new test from accidentally running the
// older integration test's schema reset against an operator-selected database.
// This test creates only a random database and application login, captures their
// OIDs, and never changes schemas in the supplied administrative database.
func TestPostgreSQLRecoveryContract(t *testing.T) {
	dsn := os.Getenv("CLOUDRING_POSTGRES_RECOVERY_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDRING_POSTGRES_RECOVERY_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("connect recovery integration service")
	}
	defer admin.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("generate unique recovery integration identity")
	}
	suffix := hex.EncodeToString(nonce[:])
	database, application := "cloudring_c06_"+suffix, "cloudring_c06_app_"+suffix
	generatedLoginValue := strings.Repeat(suffix, 2)
	var owner string
	if admin.QueryRow(ctx, "SELECT current_user").Scan(&owner) != nil {
		t.Fatal("read isolated integration owner")
	}
	roles := RecoveryRoles{Owner: owner, Application: application}
	query, err := RecoveryContractSQL(roles)
	if err != nil {
		t.Fatal(err)
	}
	appIdentifier, databaseIdentifier := pgx.Identifier{application}.Sanitize(), pgx.Identifier{database}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE ROLE "+appIdentifier+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS PASSWORD '"+generatedLoginValue+"'"); err != nil {
		t.Fatal("create unique recovery application role")
	}
	var appOID uint32
	if admin.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", application).Scan(&appOID) != nil {
		t.Fatal("capture recovery application role OID")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		var observed uint32
		if admin.QueryRow(cleanup, "SELECT oid FROM pg_roles WHERE rolname=$1", application).Scan(&observed) != nil || observed != appOID {
			t.Error("owned recovery application role changed before cleanup")
			return
		}
		if _, err := admin.Exec(cleanup, "DROP ROLE "+appIdentifier); err != nil {
			t.Error("remove owned recovery application role")
		}
	}()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+databaseIdentifier); err != nil {
		t.Fatal("create unique recovery integration database")
	}
	var databaseOID uint32
	if admin.QueryRow(ctx, "SELECT oid FROM pg_database WHERE datname=$1", database).Scan(&databaseOID) != nil {
		t.Fatal("capture recovery integration database OID")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		var observed uint32
		if admin.QueryRow(cleanup, "SELECT oid FROM pg_database WHERE datname=$1", database).Scan(&observed) != nil || observed != databaseOID {
			t.Error("owned recovery database changed before cleanup")
			return
		}
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+databaseIdentifier+" WITH (FORCE)"); err != nil {
			t.Error("remove owned recovery database")
		}
	}()
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse protected recovery integration connection")
	}
	ownerDSN := recoveryIntegrationDSN(parsed, database, owner, parsed.Password)
	connection, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatal("connect owned recovery integration database")
	}
	defer func() { _ = connection.Close(context.Background()) }()
	var connectedOID uint32
	if connection.QueryRow(ctx, "SELECT oid FROM pg_database WHERE datname=current_database()").Scan(&connectedOID) != nil || connectedOID != databaseOID {
		t.Fatal("migration is not bound to the owned recovery database")
	}
	if Migrate(ctx, Config{DSN: ownerDSN, MigrationOwnerRole: owner, ApplicationRole: application, AllowInsecureForTests: true}) != nil {
		t.Fatal("migrate owned recovery integration database")
	}
	observe := func(t *testing.T, tx pgx.Tx) (RecoveryContractObservation, string) {
		t.Helper()
		var payload []byte
		if tx.QueryRow(ctx, query).Scan(&payload) != nil {
			t.Fatal("collect real recovery catalog observation")
		}
		observation, err := DecodeRecoveryContract(payload)
		clear(payload)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := RecoveryContractSHA256(observation, roles)
		if err != nil {
			t.Fatal(err)
		}
		return observation, digest
	}
	baseline, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("start read-only recovery observation")
	}
	_, baselineDigest := observe(t, baseline)
	var readOnly, xid string
	if baseline.QueryRow(ctx, "SELECT current_setting('transaction_read_only'), COALESCE(pg_current_xact_id_if_assigned()::text, '')").Scan(&readOnly, &xid) != nil || readOnly != "on" || xid != "" {
		t.Fatal("catalog observer assigned a write transaction or escaped read-only mode")
	}
	if baseline.Commit(ctx) != nil {
		t.Fatal("finish read-only recovery observation")
	}

	appConnection, err := pgx.Connect(ctx, recoveryIntegrationDSN(parsed, database, application, generatedLoginValue))
	if err != nil {
		t.Fatal("authenticate restored least-privileged application role")
	}
	defer func() { _ = appConnection.Close(context.Background()) }()
	probe, err := appConnection.Begin(ctx)
	if err != nil {
		t.Fatal("begin recovered application allow probe")
	}
	var authenticated string
	if probe.QueryRow(ctx, "SELECT current_user").Scan(&authenticated) != nil || authenticated != application {
		t.Fatal("probe did not authenticate as the application role")
	}
	for _, statement := range []string{
		`INSERT INTO cloudring_state.documents(scope,document_key,body) VALUES ('recovery-probe','synthetic','{"value":1}')`,
		`SELECT 1 FROM cloudring_state.documents WHERE scope='recovery-probe' AND document_key='synthetic' AND revision=1 AND body='{"value":1}'::jsonb`,
		`UPDATE cloudring_state.documents SET body='{"value":2}',revision=revision+1 WHERE scope='recovery-probe' AND document_key='synthetic' AND revision=1`,
		`SELECT 1 FROM cloudring_state.documents WHERE scope='recovery-probe' AND document_key='synthetic' AND revision=2 AND body='{"value":2}'::jsonb`,
		`DELETE FROM cloudring_state.documents WHERE scope='recovery-probe' AND document_key='synthetic' AND revision=2`,
		`INSERT INTO cloudring_state.audit_journal(scope,event_id,body,payload_sha256) VALUES ('recovery-probe','synthetic','{"value":1}',repeat('a',64))`,
	} {
		command, err := probe.Exec(ctx, statement)
		if err != nil || command.RowsAffected() != 1 {
			t.Fatal("recovered application DML allow probe failed")
		}
	}
	var auditRows int
	if probe.QueryRow(ctx, `SELECT count(*) FROM cloudring_state.audit_journal WHERE scope='recovery-probe' AND event_id='synthetic' AND body='{"value":1}'::jsonb`).Scan(&auditRows) != nil || auditRows != 1 {
		t.Fatal("recovered application could not read its exact synthetic audit event")
	}
	if probe.Rollback(ctx) != nil {
		t.Fatal("roll back application allow probe")
	}
	for name, statement := range map[string]string{
		"audit-update":      `UPDATE cloudring_state.audit_journal SET body=body WHERE false`,
		"audit-delete":      `DELETE FROM cloudring_state.audit_journal WHERE false`,
		"schema-create":     `CREATE TABLE cloudring_state.denied_recovery_probe(value integer)`,
		"migration-read":    `SELECT * FROM cloudring_state.schema_migrations LIMIT 0`,
		"migration-write":   `UPDATE cloudring_state.schema_migrations SET checksum=checksum WHERE false`,
		"document-truncate": `TRUNCATE cloudring_state.documents`,
		"role-escalation":   `SET ROLE ` + pgx.Identifier{owner}.Sanitize(),
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := appConnection.Begin(ctx)
			if err != nil {
				t.Fatal("begin isolated deny probe")
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			_, err = tx.Exec(ctx, statement)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "42501" {
				t.Fatal("application denial was not insufficient_privilege")
			}
		})
	}
	var residue int
	if connection.QueryRow(ctx, "SELECT (SELECT count(*) FROM cloudring_state.documents WHERE scope='recovery-probe')+(SELECT count(*) FROM cloudring_state.audit_journal WHERE scope='recovery-probe')").Scan(&residue) != nil || residue != 0 {
		t.Fatal("application probe left synthetic rows")
	}

	t.Run("independent-unique-index-changes-application-semantics", func(t *testing.T) {
		const insert = `INSERT INTO cloudring_state.documents(scope,document_key,body) VALUES ('recovery-index','first','{}'),('recovery-index','second','{}')`
		validWrite, err := appConnection.Begin(ctx)
		if err != nil {
			t.Fatal("begin distinct-key application baseline")
		}
		command, writeErr := validWrite.Exec(ctx, insert)
		rollbackErr := validWrite.Rollback(ctx)
		if writeErr != nil || rollbackErr != nil || command.RowsAffected() != 2 {
			t.Fatal("distinct document keys were not allowed before index drift")
		}
		if _, err := connection.Exec(ctx, `CREATE UNIQUE INDEX recovery_documents_scope_unique ON cloudring_state.documents(scope)`); err != nil {
			t.Fatal("create incompatible index in owned recovery database")
		}
		t.Cleanup(func() {
			if _, err := connection.Exec(ctx, `DROP INDEX cloudring_state.recovery_documents_scope_unique`); err != nil {
				t.Error("remove owned incompatible index")
			}
		})
		_, err = appConnection.Exec(ctx, insert)
		var postgresError *pgconn.PgError
		if !errors.As(err, &postgresError) || postgresError.Code != "23505" {
			t.Fatal("unique index did not reproduce the application behavior change")
		}
		var payload []byte
		if connection.QueryRow(ctx, query).Scan(&payload) != nil {
			t.Fatal("observe committed incompatible index")
		}
		observation, err := DecodeRecoveryContract(payload)
		clear(payload)
		if err != nil {
			t.Fatal(err)
		}
		if digest, err := RecoveryContractSHA256(observation, roles); err == nil || digest != "" {
			t.Fatal("semantically incompatible unique index received a qualifying digest")
		}
		t.Log("real application distinct document keys allowed before drift; unique scope index caused SQLSTATE 23505 and recovery verification rejected it")
	})

	drifts := map[string]string{
		"wrong-table-owner":  "ALTER TABLE cloudring_state.documents OWNER TO " + appIdentifier,
		"wrong-schema-owner": "ALTER SCHEMA cloudring_state OWNER TO " + appIdentifier,
		"elevated-role":      "ALTER ROLE " + appIdentifier + " CREATEDB",
		"role-membership":    "GRANT " + pgx.Identifier{owner}.Sanitize() + " TO " + appIdentifier,
		"public-grant":       "GRANT SELECT ON cloudring_state.schema_migrations TO PUBLIC",
		"column-grant":       "GRANT SELECT(body) ON cloudring_state.documents TO PUBLIC",
		"grant-option":       "GRANT SELECT ON cloudring_state.documents TO " + appIdentifier + " WITH GRANT OPTION",
		"audit-update-grant": "GRANT UPDATE ON cloudring_state.audit_journal TO " + appIdentifier,
		"maintenance-grant":  "GRANT MAINTAIN ON cloudring_state.documents TO " + appIdentifier,
		"missing-app-grant":  "REVOKE UPDATE ON cloudring_state.documents FROM " + appIdentifier,
		"unlogged-table":     "ALTER TABLE cloudring_state.audit_journal SET UNLOGGED",
		"row-security":       "ALTER TABLE cloudring_state.documents ENABLE ROW LEVEL SECURITY",
		"changed-migration":  "UPDATE cloudring_state.schema_migrations SET checksum=repeat('1',64) WHERE version=1",
		"missing-constraint": "ALTER TABLE cloudring_state.documents DROP CONSTRAINT documents_revision_positive",
		"extra-function":     "CREATE FUNCTION cloudring_state.unexpected_recovery_function() RETURNS integer LANGUAGE SQL AS 'SELECT 1'",
		"extra-index":        "CREATE INDEX recovery_extra_index ON cloudring_state.documents(revision)",
		"expression-index":   "CREATE UNIQUE INDEX recovery_expression_index ON cloudring_state.documents(lower(scope)) WHERE revision=1",
	}
	for name, statement := range drifts {
		t.Run(name, func(t *testing.T) {
			tx, err := connection.Begin(ctx)
			if err != nil {
				t.Fatal("begin isolated catalog drift")
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if _, err := tx.Exec(ctx, statement); err != nil {
				t.Fatal("inject isolated catalog drift")
			}
			var payload []byte
			if tx.QueryRow(ctx, query).Scan(&payload) != nil {
				t.Fatal("observe isolated catalog drift")
			}
			observation, err := DecodeRecoveryContract(payload)
			clear(payload)
			if err != nil {
				t.Fatal(err)
			}
			if VerifyRecoveryContract(observation, roles) == nil {
				t.Fatal("unsafe real PostgreSQL catalog was accepted")
			}
		})
	}
	final, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("begin final read-only catalog observation")
	}
	defer func() { _ = final.Rollback(context.Background()) }()
	_, finalDigest := observe(t, final)
	if finalDigest != baselineDigest {
		t.Fatal("catalog changed after rolled-back authorization probes")
	}
	t.Log("real PostgreSQL recovery catalog: read-only/no-XID observation, app authentication and DML, SQLSTATE denials, privilege/ownership/catalog drift rejection and rollback equality passed")
}

func recoveryIntegrationDSN(parsed *pgx.ConnConfig, database, user, password string) string {
	values := url.Values{}
	values.Set("sslmode", "disable")
	connection := url.URL{Scheme: "postgresql", Host: net.JoinHostPort(parsed.Host, strconv.Itoa(int(parsed.Port))), Path: "/" + database, User: url.UserPassword(user, password), RawQuery: values.Encode()}
	return connection.String()
}
