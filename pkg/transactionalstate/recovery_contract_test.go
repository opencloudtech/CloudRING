// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package transactionalstate

import (
	"encoding/json"
	"strings"
	"testing"
)

func recoveryFixture() (RecoveryContractObservation, RecoveryRoles) {
	roles := RecoveryRoles{Owner: "recovery_owner", Application: "recovery_app"}
	o := RecoveryContractObservation{SchemaVersion: RecoveryContractSchemaVersion, Roles: roles, Database: "recovery_database", DatabaseOwner: roles.Owner, SchemaOwner: roles.Owner,
		ApplicationRole: RecoveryRole{Name: roles.Application, Inherit: true, Login: true},
		Privileges:      RecoveryPrivileges{DatabaseConnect: true, SchemaUsage: true, Documents: []string{"SELECT", "INSERT", "UPDATE", "DELETE"}, AuditJournal: []string{"SELECT", "INSERT"}, SchemaMigrations: []string{}},
	}
	for _, name := range []string{"audit_journal", "documents", "schema_migrations"} {
		o.Relations = append(o.Relations, RecoveryRelation{Name: name, Owner: roles.Owner, Kind: "r", Persistence: "p"})
	}
	for _, c := range expectedCatalogColumns(migrationVersion) {
		item := RecoveryColumn{Table: c.Table, Name: c.Name, DataType: c.DataType, NotNull: c.NotNull, Default: c.Default}
		if c.DataType == "text" {
			item.Collation = "default"
		}
		if c.Table == "audit_journal" && (c.Name == "scope" || c.Name == "event_id") {
			item.Collation = "C"
		}
		o.Columns = append(o.Columns, item)
	}
	for _, c := range expectedCatalogConstraints(migrationVersion) {
		o.Constraints = append(o.Constraints, RecoveryConstraint{Table: c.Table, Name: c.Name, Type: c.Type, Definition: c.Definition, Validated: true})
	}
	o.Indexes = expectedRecoveryIndexes(roles.Owner)
	for _, m := range expectedMigrationRecords() {
		o.Migrations = append(o.Migrations, RecoveryMigration{Version: m.Version, Checksum: m.Checksum})
	}
	return o, roles
}

func TestRecoveryContractRejectsUnsafeCatalogEvenWhenSourceAndRestoreMatch(t *testing.T) {
	mutations := map[string]func(*RecoveryContractObservation){
		"database-owner":    func(o *RecoveryContractObservation) { o.DatabaseOwner = o.Roles.Application },
		"schema-owner":      func(o *RecoveryContractObservation) { o.SchemaOwner = o.Roles.Application },
		"app-superuser":     func(o *RecoveryContractObservation) { o.ApplicationRole.Superuser = true },
		"app-createdb":      func(o *RecoveryContractObservation) { o.ApplicationRole.CreateDatabase = true },
		"app-membership":    func(o *RecoveryContractObservation) { o.ApplicationRole.MembershipCount = 1 },
		"app-no-login":      func(o *RecoveryContractObservation) { o.ApplicationRole.Login = false },
		"public-grant":      func(o *RecoveryContractObservation) { o.UnexpectedACLCount = 1 },
		"column-grant":      func(o *RecoveryContractObservation) { o.ColumnACLCount = 1 },
		"unlogged":          func(o *RecoveryContractObservation) { o.Relations[0].Persistence = "u" },
		"row-security":      func(o *RecoveryContractObservation) { o.Relations[0].RowSecurity = true },
		"table-inheritance": func(o *RecoveryContractObservation) { o.Relations[0].Inherited = true },
		"extra-relation": func(o *RecoveryContractObservation) {
			o.Relations = append(o.Relations, RecoveryRelation{Name: "extra"})
		},
		"wrong-collation":        func(o *RecoveryContractObservation) { o.Columns[0].Collation = "default" },
		"unvalidated-constraint": func(o *RecoveryContractObservation) { o.Constraints[0].Validated = false },
		"deferred-constraint":    func(o *RecoveryContractObservation) { o.Constraints[0].Deferrable = true },
		"extra-unique-index": func(o *RecoveryContractObservation) {
			o.Indexes = append(o.Indexes, RecoveryIndex{Table: "documents", Name: "scope_unique", Unique: true})
		},
		"missing-index": func(o *RecoveryContractObservation) { o.Indexes = o.Indexes[1:] },
		"index-definition": func(o *RecoveryContractObservation) {
			o.Indexes[1].Definition = "CREATE UNIQUE INDEX documents_pkey ON cloudring_state.documents USING btree (scope)"
		},
		"index-not-valid":         func(o *RecoveryContractObservation) { o.Indexes[0].Valid = false },
		"index-not-ready":         func(o *RecoveryContractObservation) { o.Indexes[0].Ready = false },
		"index-not-live":          func(o *RecoveryContractObservation) { o.Indexes[0].Live = false },
		"index-not-unique":        func(o *RecoveryContractObservation) { o.Indexes[0].Unique = false },
		"index-not-primary":       func(o *RecoveryContractObservation) { o.Indexes[0].Primary = false },
		"index-deferred":          func(o *RecoveryContractObservation) { o.Indexes[0].Immediate = false },
		"index-exclusion":         func(o *RecoveryContractObservation) { o.Indexes[0].Exclusion = true },
		"index-null-distinctness": func(o *RecoveryContractObservation) { o.Indexes[0].NullsNotDistinct = true },
		"index-link-name":         func(o *RecoveryContractObservation) { o.Indexes[0].ConstraintName = "other_pkey" },
		"index-link-type":         func(o *RecoveryContractObservation) { o.Indexes[0].ConstraintType = "u" },
		"migration-checksum":      func(o *RecoveryContractObservation) { o.Migrations[0].Checksum = strings.Repeat("a", 64) },
		"missing-grant":           func(o *RecoveryContractObservation) { o.Privileges.Documents = []string{"SELECT", "INSERT"} },
		"audit-update": func(o *RecoveryContractObservation) {
			o.Privileges.AuditJournal = append(o.Privileges.AuditJournal, "UPDATE")
		},
		"migration-access": func(o *RecoveryContractObservation) { o.Privileges.SchemaMigrations = []string{"SELECT"} },
		"database-create":  func(o *RecoveryContractObservation) { o.Privileges.DatabaseCreate = true },
		"schema-create":    func(o *RecoveryContractObservation) { o.Privileges.SchemaCreate = true },
		"extra-function":   func(o *RecoveryContractObservation) { o.FunctionCount = 1 },
		"extra-trigger":    func(o *RecoveryContractObservation) { o.UserTriggerCount = 1 },
		"extra-rule":       func(o *RecoveryContractObservation) { o.RuleCount = 1 },
		"extra-policy":     func(o *RecoveryContractObservation) { o.PolicyCount = 1 },
	}
	valid, roles := recoveryFixture()
	if _, err := RecoveryContractSHA256(valid, roles); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			observation, expected := recoveryFixture()
			mutate(&observation)
			if VerifyRecoveryContract(observation, expected) == nil {
				t.Fatal("unsafe matching catalog was accepted")
			}
			if digest, err := RecoveryContractSHA256(observation, expected); err == nil || digest != "" {
				t.Fatal("unsafe catalog received a qualifying digest")
			}
		})
	}
}

func TestRecoveryContractDecodeRequiresExplicitFalseAndZeroFacts(t *testing.T) {
	observation, roles := recoveryFixture()
	payload, _ := json.Marshal(observation)
	decoded, err := DecodeRecoveryContract(payload)
	if err != nil || VerifyRecoveryContract(decoded, roles) != nil {
		t.Fatal("complete valid observation failed")
	}
	for _, field := range []string{"unexpectedAclCount", "columnAclCount", "functionCount", "userTriggerCount", "ruleCount", "policyCount", "indexes"} {
		for _, replacement := range []string{"omit", "null"} {
			t.Run(field+"-"+replacement, func(t *testing.T) {
				var object map[string]any
				_ = json.Unmarshal(payload, &object)
				if replacement == "omit" {
					delete(object, field)
				} else {
					object[field] = nil
				}
				changed, _ := json.Marshal(object)
				if _, err := DecodeRecoveryContract(changed); err == nil {
					t.Fatal("absent required count or collection was accepted")
				}
			})
		}
	}
	var object map[string]any
	_ = json.Unmarshal(payload, &object)
	delete(object["applicationRole"].(map[string]any), "superuser")
	changed, _ := json.Marshal(object)
	if _, err := DecodeRecoveryContract(changed); err == nil {
		t.Fatal("missing superuser fact became false")
	}
	_ = json.Unmarshal(payload, &object)
	delete(object["indexes"].([]any)[0].(map[string]any), "exclusion")
	changed, _ = json.Marshal(object)
	if _, err := DecodeRecoveryContract(changed); err == nil {
		t.Fatal("missing index exclusion fact became false")
	}
	if _, err := DecodeRecoveryContract(append([]byte(`{"schemaVersion":"duplicate",`), payload[1:]...)); err == nil {
		t.Fatal("duplicate field was accepted")
	}
}

func TestRecoveryContractRoleInputsAreExplicitAndBound(t *testing.T) {
	for _, roles := range []RecoveryRoles{{}, {Owner: "owner", Application: "owner"}, {Owner: "owner'", Application: "app"}, {Owner: "owner", Application: "app;select"}, {Owner: " owner", Application: "app"}} {
		if query, err := RecoveryContractSQL(roles); err == nil || query != "" {
			t.Fatal("unsafe or implicit role was interpolated")
		}
	}
	observation, roles := recoveryFixture()
	roles.Application = "other_app"
	if VerifyRecoveryContract(observation, roles) == nil {
		t.Fatal("observation was detached from expected roles")
	}
}
