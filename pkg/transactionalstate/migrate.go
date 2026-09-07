// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package transactionalstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	migrationVersion       = 2
	defaultMigrationOwner  = "cloudring_owner"
	defaultApplicationRole = "cloudring_app"
)

var (
	postgresRolePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	migrationOneSQL     = []string{
		`CREATE SCHEMA cloudring_state AUTHORIZATION {{owner}}`,
		`CREATE TABLE cloudring_state.schema_migrations (
			version integer CONSTRAINT schema_migrations_pkey PRIMARY KEY,
			checksum text NOT NULL CONSTRAINT schema_migrations_checksum_format CHECK (checksum ~ '^[0-9a-f]{64}$'),
			applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
		)`,
		`CREATE TABLE cloudring_state.documents (
			scope text NOT NULL,
			document_key text NOT NULL,
			revision bigint NOT NULL DEFAULT 1 CONSTRAINT documents_revision_positive CHECK (revision > 0),
			body jsonb NOT NULL,
			updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
			CONSTRAINT documents_pkey PRIMARY KEY (scope, document_key),
			CONSTRAINT documents_scope_format CHECK (scope ~ '^[a-z0-9][a-z0-9._:-]{0,127}$'),
			CONSTRAINT documents_key_format CHECK (document_key ~ '^[a-z0-9][a-z0-9._:-]{0,127}$'),
			CONSTRAINT documents_body_size CHECK (octet_length(body::text) <= 8388608)
		)`,
		`REVOKE ALL PRIVILEGES ON SCHEMA cloudring_state FROM PUBLIC`,
		`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA cloudring_state FROM PUBLIC`,
		`REVOKE ALL PRIVILEGES ON SCHEMA cloudring_state FROM {{application}}`,
		`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA cloudring_state FROM {{application}}`,
		`GRANT USAGE ON SCHEMA cloudring_state TO {{application}}`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE cloudring_state.documents TO {{application}}`,
	}
	migrationTwoSQL = []string{
		`CREATE TABLE cloudring_state.audit_journal (
			scope text COLLATE "C" NOT NULL,
			event_id text COLLATE "C" NOT NULL,
			body jsonb NOT NULL,
			payload_sha256 text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
			CONSTRAINT audit_journal_pkey PRIMARY KEY (scope, event_id),
			CONSTRAINT audit_journal_scope_format CHECK (scope ~ '^[a-z0-9][a-z0-9._:-]{0,127}$'),
			CONSTRAINT audit_journal_event_id_format CHECK (event_id ~ '^[a-z0-9][a-z0-9._:-]{0,127}$'),
			CONSTRAINT audit_journal_payload_sha256_format CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
			CONSTRAINT audit_journal_body_size CHECK (octet_length(body::text) <= 262144)
		)`,
		`REVOKE ALL PRIVILEGES ON TABLE cloudring_state.audit_journal FROM PUBLIC`,
		`REVOKE ALL PRIVILEGES ON TABLE cloudring_state.audit_journal FROM {{application}}`,
		`GRANT SELECT, INSERT ON TABLE cloudring_state.audit_journal TO {{application}}`,
	}
)

type catalogColumn struct {
	Table    string
	Name     string
	DataType string
	NotNull  bool
	Default  string
}

type catalogConstraint struct {
	Table      string
	Name       string
	Type       string
	Definition string
}

type catalogRelation struct {
	Name  string
	Owner string
	Kind  string
}

// Migrate applies additive schema versions under a transaction-scoped advisory
// lock. It creates only a completely absent schema and otherwise verifies the
// recorded checksums, catalog shape, ownership, and effective privileges before
// applying the next version. Unexpected pre-existing objects are never repaired
// or blessed.
func Migrate(ctx context.Context, config Config) error {
	ownerRole, applicationRole, err := migrationRoles(config)
	if err != nil {
		return errors.New("transactional state migration configuration is invalid")
	}
	poolConfig, operationTimeout, err := poolConfiguration(config)
	if err != nil || ctx == nil {
		return errors.New("transactional state migration configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("open transactional state migration database")
	}
	defer pool.Close()
	migrationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	tx, err := pool.Begin(migrationCtx)
	if err != nil {
		return errors.New("begin transactional state migration")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(migrationCtx, `SELECT pg_advisory_xact_lock(48513070420260203)`); err != nil {
		return errors.New("lock transactional state migration")
	}
	if err := verifyMigrationRoles(migrationCtx, tx, ownerRole, applicationRole); err != nil {
		return errors.New("verify transactional state migration identities")
	}

	var schemaExists, migrationTableExists, documentsTableExists, auditJournalTableExists bool
	if err := tx.QueryRow(migrationCtx, `
		SELECT
			to_regnamespace('cloudring_state') IS NOT NULL,
			to_regclass('cloudring_state.schema_migrations') IS NOT NULL,
			to_regclass('cloudring_state.documents') IS NOT NULL,
			to_regclass('cloudring_state.audit_journal') IS NOT NULL
	`).Scan(&schemaExists, &migrationTableExists, &documentsTableExists, &auditJournalTableExists); err != nil {
		return errors.New("inspect transactional state migration")
	}
	if !schemaExists && !migrationTableExists && !documentsTableExists && !auditJournalTableExists {
		statements := renderedMigrationOne(ownerRole, applicationRole)
		for _, statement := range statements {
			if _, err := tx.Exec(migrationCtx, statement); err != nil {
				return errors.New("apply transactional state migration")
			}
		}
		if _, err := tx.Exec(migrationCtx, `
			INSERT INTO cloudring_state.schema_migrations (version, checksum)
			VALUES ($1, $2)
		`, 1, migrationOneChecksum()); err != nil {
			return errors.New("record transactional state migration")
		}
	} else if !schemaExists || !migrationTableExists || !documentsTableExists {
		return errors.New("transactional state schema conflicts with migration history")
	}
	versions, err := readMigrationRecords(migrationCtx, tx)
	if err != nil {
		return errors.New("verify transactional state migration history")
	}
	if reflect.DeepEqual(versions, []migrationRecord{{Version: 1, Checksum: migrationOneChecksum()}}) {
		if auditJournalTableExists || verifyMigrationContract(migrationCtx, tx, ownerRole, applicationRole, 1) != nil {
			return errors.New("verify transactional state migration contract")
		}
		for _, statement := range renderedMigrationTwo(applicationRole) {
			if _, err := tx.Exec(migrationCtx, statement); err != nil {
				return errors.New("apply transactional state migration")
			}
		}
		if _, err := tx.Exec(migrationCtx, `
			INSERT INTO cloudring_state.schema_migrations (version, checksum)
			VALUES ($1, $2)
		`, 2, migrationTwoChecksum()); err != nil {
			return errors.New("record transactional state migration")
		}
	} else if !reflect.DeepEqual(versions, expectedMigrationRecords()) {
		return errors.New("verify transactional state migration history")
	}
	if err := verifyMigrationRecord(migrationCtx, tx); err != nil {
		return errors.New("verify transactional state migration history")
	}
	if err := verifyMigrationContract(migrationCtx, tx, ownerRole, applicationRole, migrationVersion); err != nil {
		return errors.New("verify transactional state migration contract")
	}
	if err := tx.Commit(migrationCtx); err != nil {
		return errors.New("commit transactional state migration")
	}
	return nil
}

func migrationRoles(config Config) (string, string, error) {
	owner := strings.TrimSpace(config.MigrationOwnerRole)
	if owner == "" {
		owner = defaultMigrationOwner
	}
	application := strings.TrimSpace(config.ApplicationRole)
	if application == "" {
		application = defaultApplicationRole
	}
	if owner == application || !postgresRolePattern.MatchString(owner) || !postgresRolePattern.MatchString(application) {
		return "", "", errors.New("database roles are invalid")
	}
	return owner, application, nil
}

func renderedMigrationOne(ownerRole, applicationRole string) []string {
	owner := pgx.Identifier{ownerRole}.Sanitize()
	application := pgx.Identifier{applicationRole}.Sanitize()
	replacer := strings.NewReplacer("{{owner}}", owner, "{{application}}", application)
	statements := make([]string, 0, len(migrationOneSQL))
	for _, statement := range migrationOneSQL {
		statements = append(statements, replacer.Replace(statement))
	}
	return statements
}

func renderedMigrationTwo(applicationRole string) []string {
	application := pgx.Identifier{applicationRole}.Sanitize()
	replacer := strings.NewReplacer("{{application}}", application)
	statements := make([]string, 0, len(migrationTwoSQL))
	for _, statement := range migrationTwoSQL {
		statements = append(statements, replacer.Replace(statement))
	}
	return statements
}

func verifyMigrationRoles(ctx context.Context, tx pgx.Tx, ownerRole, applicationRole string) error {
	var currentUser, databaseOwner string
	if err := tx.QueryRow(ctx, `
		SELECT current_user, pg_get_userbyid(datdba)
		FROM pg_database
		WHERE datname = current_database()
	`).Scan(&currentUser, &databaseOwner); err != nil || currentUser != ownerRole || databaseOwner != ownerRole {
		return errors.New("migration owner is invalid")
	}
	return verifyApplicationRole(ctx, tx, applicationRole)
}

func verifyApplicationRole(ctx context.Context, tx pgx.Tx, applicationRole string) error {
	var superuser, inherit, createRole, createDatabase, login, replication, bypassRLS bool
	if err := tx.QueryRow(ctx, `
		SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls
		FROM pg_roles
		WHERE rolname = $1
	`, applicationRole).Scan(&superuser, &inherit, &createRole, &createDatabase, &login, &replication, &bypassRLS); err != nil ||
		superuser || !inherit || createRole || createDatabase || !login || replication || bypassRLS {
		return errors.New("application role is not least-privileged")
	}
	var memberships int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_auth_members
		WHERE member = (SELECT oid FROM pg_roles WHERE rolname = $1)
	`, applicationRole).Scan(&memberships); err != nil || memberships != 0 {
		return errors.New("application role has inherited memberships")
	}
	return nil
}

type migrationRecord struct {
	Version  int
	Checksum string
}

func readMigrationRecords(ctx context.Context, tx pgx.Tx) ([]migrationRecord, error) {
	rows, err := tx.Query(ctx, `
		SELECT version, checksum
		FROM cloudring_state.schema_migrations
		ORDER BY version
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []migrationRecord
	for rows.Next() {
		var record migrationRecord
		if err := rows.Scan(&record.Version, &record.Checksum); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func expectedMigrationRecords() []migrationRecord {
	return []migrationRecord{
		{Version: 1, Checksum: migrationOneChecksum()},
		{Version: 2, Checksum: migrationTwoChecksum()},
	}
}

func verifyMigrationRecord(ctx context.Context, tx pgx.Tx) error {
	records, err := readMigrationRecords(ctx, tx)
	if err != nil || !reflect.DeepEqual(records, expectedMigrationRecords()) {
		return errors.New("migration history is invalid")
	}
	return nil
}

func verifyMigrationContract(ctx context.Context, tx pgx.Tx, ownerRole, applicationRole string, version int) error {
	expectedRelations := []catalogRelation{
		{Name: "documents", Owner: ownerRole, Kind: "r"},
		{Name: "schema_migrations", Owner: ownerRole, Kind: "r"},
	}
	if version >= 2 {
		expectedRelations = append([]catalogRelation{{Name: "audit_journal", Owner: ownerRole, Kind: "r"}}, expectedRelations...)
	}
	relations, err := readCatalogRelations(ctx, tx)
	if err != nil || !reflect.DeepEqual(relations, expectedRelations) {
		return errors.New("database relation inventory is invalid")
	}
	var schemaOwner string
	if err := tx.QueryRow(ctx, `
		SELECT pg_get_userbyid(nspowner)
		FROM pg_namespace
		WHERE nspname = 'cloudring_state'
	`).Scan(&schemaOwner); err != nil || schemaOwner != ownerRole {
		return errors.New("database schema owner is invalid")
	}
	columns, err := readCatalogColumns(ctx, tx)
	if err != nil || !reflect.DeepEqual(columns, expectedCatalogColumns(version)) {
		return errors.New("database column contract is invalid")
	}
	constraints, err := readCatalogConstraints(ctx, tx)
	if err != nil || !reflect.DeepEqual(constraints, expectedCatalogConstraints(version)) {
		return errors.New("database constraint contract is invalid")
	}
	if err := verifyApplicationPrivileges(ctx, tx, applicationRole, version); err != nil {
		return err
	}
	return nil
}

func readCatalogRelations(ctx context.Context, tx pgx.Tx) ([]catalogRelation, error) {
	rows, err := tx.Query(ctx, `
		SELECT c.relname, pg_get_userbyid(c.relowner), c.relkind::text
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'cloudring_state'
		  AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
		ORDER BY c.relname
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []catalogRelation
	for rows.Next() {
		var item catalogRelation
		if err := rows.Scan(&item.Name, &item.Owner, &item.Kind); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func readCatalogColumns(ctx context.Context, tx pgx.Tx) ([]catalogColumn, error) {
	rows, err := tx.Query(ctx, `
		SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
		       COALESCE(pg_get_expr(ad.adbin, ad.adrelid), '')
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		LEFT JOIN pg_attrdef ad ON ad.adrelid = c.oid AND ad.adnum = a.attnum
		WHERE n.nspname = 'cloudring_state' AND c.relkind = 'r'
		ORDER BY c.relname, a.attnum
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []catalogColumn
	for rows.Next() {
		var item catalogColumn
		if err := rows.Scan(&item.Table, &item.Name, &item.DataType, &item.NotNull, &item.Default); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func readCatalogConstraints(ctx context.Context, tx pgx.Tx) ([]catalogConstraint, error) {
	rows, err := tx.Query(ctx, `
		SELECT c.relname, con.conname, con.contype::text, pg_get_constraintdef(con.oid, false)
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'cloudring_state' AND con.contype != 'n'
		ORDER BY c.relname, con.conname
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []catalogConstraint
	for rows.Next() {
		var item catalogConstraint
		if err := rows.Scan(&item.Table, &item.Name, &item.Type, &item.Definition); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func expectedCatalogColumns(version int) []catalogColumn {
	columns := []catalogColumn{}
	if version >= 2 {
		columns = append(columns,
			catalogColumn{Table: "audit_journal", Name: "scope", DataType: "text", NotNull: true},
			catalogColumn{Table: "audit_journal", Name: "event_id", DataType: "text", NotNull: true},
			catalogColumn{Table: "audit_journal", Name: "body", DataType: "jsonb", NotNull: true},
			catalogColumn{Table: "audit_journal", Name: "payload_sha256", DataType: "text", NotNull: true},
			catalogColumn{Table: "audit_journal", Name: "created_at", DataType: "timestamp with time zone", NotNull: true, Default: "clock_timestamp()"},
		)
	}
	return append(columns,
		catalogColumn{Table: "documents", Name: "scope", DataType: "text", NotNull: true},
		catalogColumn{Table: "documents", Name: "document_key", DataType: "text", NotNull: true},
		catalogColumn{Table: "documents", Name: "revision", DataType: "bigint", NotNull: true, Default: "1"},
		catalogColumn{Table: "documents", Name: "body", DataType: "jsonb", NotNull: true},
		catalogColumn{Table: "documents", Name: "updated_at", DataType: "timestamp with time zone", NotNull: true, Default: "clock_timestamp()"},
		catalogColumn{Table: "schema_migrations", Name: "version", DataType: "integer", NotNull: true},
		catalogColumn{Table: "schema_migrations", Name: "checksum", DataType: "text", NotNull: true},
		catalogColumn{Table: "schema_migrations", Name: "applied_at", DataType: "timestamp with time zone", NotNull: true, Default: "clock_timestamp()"},
	)
}

func expectedCatalogConstraints(version int) []catalogConstraint {
	constraints := []catalogConstraint{}
	if version >= 2 {
		constraints = append(constraints,
			catalogConstraint{Table: "audit_journal", Name: "audit_journal_body_size", Type: "c", Definition: "CHECK ((octet_length((body)::text) <= 262144))"},
			catalogConstraint{Table: "audit_journal", Name: "audit_journal_event_id_format", Type: "c", Definition: "CHECK ((event_id ~ '^[a-z0-9][a-z0-9._:-]{0,127}$'::text))"},
			catalogConstraint{Table: "audit_journal", Name: "audit_journal_payload_sha256_format", Type: "c", Definition: "CHECK ((payload_sha256 ~ '^[0-9a-f]{64}$'::text))"},
			catalogConstraint{Table: "audit_journal", Name: "audit_journal_pkey", Type: "p", Definition: "PRIMARY KEY (scope, event_id)"},
			catalogConstraint{Table: "audit_journal", Name: "audit_journal_scope_format", Type: "c", Definition: "CHECK ((scope ~ '^[a-z0-9][a-z0-9._:-]{0,127}$'::text))"},
		)
	}
	return append(constraints,
		catalogConstraint{Table: "documents", Name: "documents_body_size", Type: "c", Definition: "CHECK ((octet_length((body)::text) <= 8388608))"},
		catalogConstraint{Table: "documents", Name: "documents_key_format", Type: "c", Definition: "CHECK ((document_key ~ '^[a-z0-9][a-z0-9._:-]{0,127}$'::text))"},
		catalogConstraint{Table: "documents", Name: "documents_pkey", Type: "p", Definition: "PRIMARY KEY (scope, document_key)"},
		catalogConstraint{Table: "documents", Name: "documents_revision_positive", Type: "c", Definition: "CHECK ((revision > 0))"},
		catalogConstraint{Table: "documents", Name: "documents_scope_format", Type: "c", Definition: "CHECK ((scope ~ '^[a-z0-9][a-z0-9._:-]{0,127}$'::text))"},
		catalogConstraint{Table: "schema_migrations", Name: "schema_migrations_checksum_format", Type: "c", Definition: "CHECK ((checksum ~ '^[0-9a-f]{64}$'::text))"},
		catalogConstraint{Table: "schema_migrations", Name: "schema_migrations_pkey", Type: "p", Definition: "PRIMARY KEY (version)"},
	)
}

func verifyApplicationPrivileges(ctx context.Context, tx pgx.Tx, applicationRole string, version int) error {
	var schemaUsage, schemaCreate bool
	var selectDocument, insertDocument, updateDocument, deleteDocument bool
	var truncateDocument, referencesDocument, triggerDocument, maintainDocument bool
	if err := tx.QueryRow(ctx, `
		SELECT
			has_schema_privilege($1, 'cloudring_state', 'USAGE'),
			has_schema_privilege($1, 'cloudring_state', 'CREATE'),
			has_table_privilege($1, 'cloudring_state.documents', 'SELECT'),
			has_table_privilege($1, 'cloudring_state.documents', 'INSERT'),
			has_table_privilege($1, 'cloudring_state.documents', 'UPDATE'),
			has_table_privilege($1, 'cloudring_state.documents', 'DELETE'),
			has_table_privilege($1, 'cloudring_state.documents', 'TRUNCATE'),
			has_table_privilege($1, 'cloudring_state.documents', 'REFERENCES'),
			has_table_privilege($1, 'cloudring_state.documents', 'TRIGGER'),
			has_table_privilege($1, 'cloudring_state.documents', 'MAINTAIN')
	`, applicationRole).Scan(
		&schemaUsage, &schemaCreate, &selectDocument, &insertDocument, &updateDocument,
		&deleteDocument, &truncateDocument, &referencesDocument, &triggerDocument, &maintainDocument,
	); err != nil || !schemaUsage || schemaCreate || !selectDocument || !insertDocument || !updateDocument || !deleteDocument || truncateDocument || referencesDocument || triggerDocument || maintainDocument {
		return errors.New("application document privileges are invalid")
	}
	if version >= 2 {
		var selectJournal, insertJournal, updateJournal, deleteJournal bool
		var truncateJournal, referencesJournal, triggerJournal, maintainJournal bool
		if err := tx.QueryRow(ctx, `
			SELECT
				has_table_privilege($1, 'cloudring_state.audit_journal', 'SELECT'),
				has_table_privilege($1, 'cloudring_state.audit_journal', 'INSERT'),
				has_table_privilege($1, 'cloudring_state.audit_journal', 'UPDATE'),
				has_table_privilege($1, 'cloudring_state.audit_journal', 'DELETE'),
				has_table_privilege($1, 'cloudring_state.audit_journal', 'TRUNCATE'),
				has_table_privilege($1, 'cloudring_state.audit_journal', 'REFERENCES'),
				has_table_privilege($1, 'cloudring_state.audit_journal', 'TRIGGER'),
				has_table_privilege($1, 'cloudring_state.audit_journal', 'MAINTAIN')
		`, applicationRole).Scan(
			&selectJournal, &insertJournal, &updateJournal, &deleteJournal,
			&truncateJournal, &referencesJournal, &triggerJournal, &maintainJournal,
		); err != nil || !selectJournal || !insertJournal || updateJournal || deleteJournal || truncateJournal || referencesJournal || triggerJournal || maintainJournal {
			return errors.New("application audit journal privileges are invalid")
		}
	}
	for _, role := range []string{applicationRole, "public"} {
		var usage, create, migrationsAny bool
		if err := tx.QueryRow(ctx, `
			SELECT
				has_schema_privilege($1, 'cloudring_state', 'USAGE'),
				has_schema_privilege($1, 'cloudring_state', 'CREATE'),
				has_table_privilege($1, 'cloudring_state.schema_migrations', 'SELECT') OR
				has_table_privilege($1, 'cloudring_state.schema_migrations', 'INSERT') OR
				has_table_privilege($1, 'cloudring_state.schema_migrations', 'UPDATE') OR
				has_table_privilege($1, 'cloudring_state.schema_migrations', 'DELETE') OR
				has_table_privilege($1, 'cloudring_state.schema_migrations', 'TRUNCATE') OR
				has_table_privilege($1, 'cloudring_state.schema_migrations', 'REFERENCES') OR
				has_table_privilege($1, 'cloudring_state.schema_migrations', 'TRIGGER') OR
				has_table_privilege($1, 'cloudring_state.schema_migrations', 'MAINTAIN')
		`, role).Scan(&usage, &create, &migrationsAny); err != nil || create || migrationsAny || (role == "public" && usage) {
			return errors.New("schema or migration privileges are invalid")
		}
	}
	var publicDocumentPrivileges bool
	if err := tx.QueryRow(ctx, `
		SELECT
			has_table_privilege('public', 'cloudring_state.documents', 'SELECT') OR
			has_table_privilege('public', 'cloudring_state.documents', 'INSERT') OR
			has_table_privilege('public', 'cloudring_state.documents', 'UPDATE') OR
			has_table_privilege('public', 'cloudring_state.documents', 'DELETE') OR
			has_table_privilege('public', 'cloudring_state.documents', 'TRUNCATE') OR
			has_table_privilege('public', 'cloudring_state.documents', 'REFERENCES') OR
			has_table_privilege('public', 'cloudring_state.documents', 'TRIGGER') OR
			has_table_privilege('public', 'cloudring_state.documents', 'MAINTAIN')
	`).Scan(&publicDocumentPrivileges); err != nil || publicDocumentPrivileges {
		return errors.New("public document privileges are invalid")
	}
	if version >= 2 {
		var publicJournalPrivileges bool
		if err := tx.QueryRow(ctx, `
			SELECT
				has_table_privilege('public', 'cloudring_state.audit_journal', 'SELECT') OR
				has_table_privilege('public', 'cloudring_state.audit_journal', 'INSERT') OR
				has_table_privilege('public', 'cloudring_state.audit_journal', 'UPDATE') OR
				has_table_privilege('public', 'cloudring_state.audit_journal', 'DELETE') OR
				has_table_privilege('public', 'cloudring_state.audit_journal', 'TRUNCATE') OR
				has_table_privilege('public', 'cloudring_state.audit_journal', 'REFERENCES') OR
				has_table_privilege('public', 'cloudring_state.audit_journal', 'TRIGGER') OR
				has_table_privilege('public', 'cloudring_state.audit_journal', 'MAINTAIN')
		`).Scan(&publicJournalPrivileges); err != nil || publicJournalPrivileges {
			return errors.New("public audit journal privileges are invalid")
		}
	}
	return nil
}

func migrationOneChecksum() string {
	sum := sha256.Sum256([]byte(strings.Join(migrationOneSQL, "\x00")))
	return hex.EncodeToString(sum[:])
}

func migrationTwoChecksum() string {
	sum := sha256.Sum256([]byte(strings.Join(migrationTwoSQL, "\x00")))
	return hex.EncodeToString(sum[:])
}
