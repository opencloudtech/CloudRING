// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package transactionalstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const RecoveryContractSchemaVersion = "cloudring.transactional-state.recovery-contract/v1"

// RecoveryRoles are the expected restored object owner and application role.
// Both are explicit: a recovery observer must not infer them from the current
// administrative connection or from an unverified database owner.
type RecoveryRoles struct {
	Owner       string `json:"owner"`
	Application string `json:"application"`
}

type RecoveryRole struct {
	Name            string `json:"name"`
	Superuser       bool   `json:"superuser"`
	Inherit         bool   `json:"inherit"`
	CreateRole      bool   `json:"createRole"`
	CreateDatabase  bool   `json:"createDatabase"`
	Login           bool   `json:"login"`
	Replication     bool   `json:"replication"`
	BypassRLS       bool   `json:"bypassRls"`
	MembershipCount int    `json:"membershipCount"`
}

type RecoveryRelation struct {
	Name             string `json:"name"`
	Owner            string `json:"owner"`
	Kind             string `json:"kind"`
	Persistence      string `json:"persistence"`
	RowSecurity      bool   `json:"rowSecurity"`
	ForceRowSecurity bool   `json:"forceRowSecurity"`
	Inherited        bool   `json:"inherited"`
}

type RecoveryColumn struct {
	Table     string `json:"table"`
	Name      string `json:"name"`
	DataType  string `json:"dataType"`
	NotNull   bool   `json:"notNull"`
	Default   string `json:"default"`
	Collation string `json:"collation"`
	Identity  string `json:"identity"`
	Generated string `json:"generated"`
}

type RecoveryConstraint struct {
	Table             string `json:"table"`
	Name              string `json:"name"`
	Type              string `json:"type"`
	Definition        string `json:"definition"`
	Validated         bool   `json:"validated"`
	Deferrable        bool   `json:"deferrable"`
	InitiallyDeferred bool   `json:"initiallyDeferred"`
}

// RecoveryIndex includes behavior and usability that table constraints alone
// cannot establish, including independent unique or expression indexes.
type RecoveryIndex struct {
	Table            string `json:"table"`
	Name             string `json:"name"`
	Owner            string `json:"owner"`
	Kind             string `json:"kind"`
	Persistence      string `json:"persistence"`
	Definition       string `json:"definition"`
	Unique           bool   `json:"unique"`
	Primary          bool   `json:"primary"`
	Exclusion        bool   `json:"exclusion"`
	Immediate        bool   `json:"immediate"`
	Valid            bool   `json:"valid"`
	Ready            bool   `json:"ready"`
	Live             bool   `json:"live"`
	NullsNotDistinct bool   `json:"nullsNotDistinct"`
	ConstraintName   string `json:"constraintName"`
	ConstraintType   string `json:"constraintType"`
}

type RecoveryMigration struct {
	Version  int    `json:"version"`
	Checksum string `json:"checksum"`
}

type RecoveryPrivileges struct {
	DatabaseConnect   bool     `json:"databaseConnect"`
	DatabaseCreate    bool     `json:"databaseCreate"`
	DatabaseTemporary bool     `json:"databaseTemporary"`
	SchemaUsage       bool     `json:"schemaUsage"`
	SchemaCreate      bool     `json:"schemaCreate"`
	Documents         []string `json:"documents"`
	AuditJournal      []string `json:"auditJournal"`
	SchemaMigrations  []string `json:"schemaMigrations"`
}

// RecoveryContractObservation contains catalog metadata and effective access
// facts only. It contains no database rows, password verifiers or credentials.
// Collect it in the same read-only snapshot as the protected logical digest.
type RecoveryContractObservation struct {
	SchemaVersion      string               `json:"schemaVersion"`
	Roles              RecoveryRoles        `json:"roles"`
	Database           string               `json:"database"`
	DatabaseOwner      string               `json:"databaseOwner"`
	SchemaOwner        string               `json:"schemaOwner"`
	ApplicationRole    RecoveryRole         `json:"applicationRole"`
	Relations          []RecoveryRelation   `json:"relations"`
	Columns            []RecoveryColumn     `json:"columns"`
	Constraints        []RecoveryConstraint `json:"constraints"`
	Indexes            []RecoveryIndex      `json:"indexes"`
	Migrations         []RecoveryMigration  `json:"migrations"`
	Privileges         RecoveryPrivileges   `json:"privileges"`
	UnexpectedACLCount int                  `json:"unexpectedAclCount"`
	ColumnACLCount     int                  `json:"columnAclCount"`
	FunctionCount      int                  `json:"functionCount"`
	UserTriggerCount   int                  `json:"userTriggerCount"`
	RuleCount          int                  `json:"ruleCount"`
	PolicyCount        int                  `json:"policyCount"`
}

// RecoveryContractSQL returns a single read-only SELECT. It does not start or
// commit a transaction, migrate a schema, take an advisory lock, repair grants,
// or change session authorization. A caller may include it in an existing
// repeatable-read source/restore observation through pgx or protected psql.
func RecoveryContractSQL(roles RecoveryRoles) (string, error) {
	if !validRecoveryRoles(roles) {
		return "", errors.New("recovery contract roles are invalid")
	}
	return strings.NewReplacer("{{owner}}", roles.Owner, "{{application}}", roles.Application, "{{schema}}", RecoveryContractSchemaVersion).Replace(recoveryContractQuery), nil
}

// DecodeRecoveryContract requires every JSON field, including false denial
// facts and zero counts. Omitted/null facts cannot become Go zero-value proof.
func DecodeRecoveryContract(payload []byte) (RecoveryContractObservation, error) {
	var observation RecoveryContractObservation
	if len(payload) > 256<<10 || strictjson.DecodeExact(payload, &observation) != nil || observation.Indexes == nil {
		return observation, errors.New("recovery contract observation is invalid")
	}
	canonical, err := json.Marshal(observation)
	if err != nil {
		return RecoveryContractObservation{}, errors.New("recovery contract observation is invalid")
	}
	var received, expected any
	if strictjson.Decode(payload, &received) != nil || strictjson.Decode(canonical, &expected) != nil || !reflect.DeepEqual(received, expected) {
		return RecoveryContractObservation{}, errors.New("recovery contract observation contains omitted or null facts")
	}
	return observation, nil
}

// VerifyRecoveryContract compares observed ownership, migration/catalog shape,
// and effective application access against the existing migration contract.
// Matching source and restored observations must each pass this check; equality
// alone cannot qualify two equally overprivileged databases. This is catalog
// authorization evidence, not proof of application authentication or DML.
func VerifyRecoveryContract(observation RecoveryContractObservation, roles RecoveryRoles) error {
	if !validRecoveryRoles(roles) || observation.SchemaVersion != RecoveryContractSchemaVersion || observation.Roles != roles || observation.Database == "" || len(observation.Database) > 63 || observation.DatabaseOwner != roles.Owner || observation.SchemaOwner != roles.Owner {
		return errors.New("recovery database or schema ownership is invalid")
	}
	app := observation.ApplicationRole
	if app.Name != roles.Application || app.Superuser || !app.Inherit || app.CreateRole || app.CreateDatabase || !app.Login || app.Replication || app.BypassRLS || app.MembershipCount != 0 {
		return errors.New("recovery application role is not least-privileged")
	}
	if observation.UnexpectedACLCount != 0 || observation.ColumnACLCount != 0 || observation.FunctionCount != 0 || observation.UserTriggerCount != 0 || observation.RuleCount != 0 || observation.PolicyCount != 0 {
		return errors.New("recovery schema contains unexpected access or behavior")
	}
	expectedRelations := []RecoveryRelation{
		{Name: "audit_journal", Owner: roles.Owner, Kind: "r", Persistence: "p"},
		{Name: "documents", Owner: roles.Owner, Kind: "r", Persistence: "p"},
		{Name: "schema_migrations", Owner: roles.Owner, Kind: "r", Persistence: "p"},
	}
	if !reflect.DeepEqual(observation.Relations, expectedRelations) {
		return errors.New("recovery relation contract is invalid")
	}
	columns := make([]RecoveryColumn, 0)
	for _, expected := range expectedCatalogColumns(migrationVersion) {
		column := RecoveryColumn{Table: expected.Table, Name: expected.Name, DataType: expected.DataType, NotNull: expected.NotNull, Default: expected.Default}
		if expected.DataType == "text" {
			column.Collation = "default"
		}
		if expected.Table == "audit_journal" && (expected.Name == "scope" || expected.Name == "event_id") {
			column.Collation = "C"
		}
		columns = append(columns, column)
	}
	if !reflect.DeepEqual(observation.Columns, columns) {
		return errors.New("recovery column contract is invalid")
	}
	constraints := make([]RecoveryConstraint, 0)
	for _, expected := range expectedCatalogConstraints(migrationVersion) {
		constraints = append(constraints, RecoveryConstraint{Table: expected.Table, Name: expected.Name, Type: expected.Type, Definition: expected.Definition, Validated: true})
	}
	if !reflect.DeepEqual(observation.Constraints, constraints) {
		return errors.New("recovery constraint contract is invalid")
	}
	if !reflect.DeepEqual(observation.Indexes, expectedRecoveryIndexes(roles.Owner)) {
		return errors.New("recovery index contract is invalid")
	}
	migrations := make([]RecoveryMigration, 0)
	for _, expected := range expectedMigrationRecords() {
		migrations = append(migrations, RecoveryMigration{Version: expected.Version, Checksum: expected.Checksum})
	}
	if !reflect.DeepEqual(observation.Migrations, migrations) {
		return errors.New("recovery migration history is invalid")
	}
	privileges := observation.Privileges
	if !privileges.DatabaseConnect || privileges.DatabaseCreate || !privileges.SchemaUsage || privileges.SchemaCreate ||
		!reflect.DeepEqual(privileges.Documents, []string{"SELECT", "INSERT", "UPDATE", "DELETE"}) ||
		!reflect.DeepEqual(privileges.AuditJournal, []string{"SELECT", "INSERT"}) ||
		!reflect.DeepEqual(privileges.SchemaMigrations, []string{}) {
		return errors.New("recovery application privileges are invalid")
	}
	return nil
}

// RecoveryContractSHA256 returns the unprefixed canonical digest only for a
// contract that passes verification. The source and restored digest must both
// be retained by the enclosing recovery receipt.
func RecoveryContractSHA256(observation RecoveryContractObservation, roles RecoveryRoles) (string, error) {
	if err := VerifyRecoveryContract(observation, roles); err != nil {
		return "", err
	}
	payload, err := json.Marshal(observation)
	if err != nil {
		return "", errors.New("encode recovery contract digest")
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func validRecoveryRoles(roles RecoveryRoles) bool {
	return roles.Owner != roles.Application && postgresRolePattern.MatchString(roles.Owner) && postgresRolePattern.MatchString(roles.Application)
}

func expectedRecoveryIndexes(owner string) []RecoveryIndex {
	// Current migrations create only the three primary-key indexes. Keep this
	// inventory tied to their constraints; a future standalone migration index
	// needs an explicit supported definition here before recovery can qualify.
	indexes := []RecoveryIndex{}
	for _, constraint := range expectedCatalogConstraints(migrationVersion) {
		if constraint.Type != "p" {
			continue
		}
		indexes = append(indexes, RecoveryIndex{
			Table: constraint.Table, Name: constraint.Name, Owner: owner, Kind: "i", Persistence: "p",
			Definition: "CREATE UNIQUE INDEX " + constraint.Name + " ON cloudring_state." + constraint.Table + " USING btree " + strings.TrimPrefix(constraint.Definition, "PRIMARY KEY "),
			Unique:     true, Primary: true, Immediate: true, Valid: true, Ready: true, Live: true,
			ConstraintName: constraint.Name, ConstraintType: constraint.Type,
		})
	}
	return indexes
}
