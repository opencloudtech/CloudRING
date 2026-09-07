// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package platformmanifest

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/opencloudtech/CloudRING/pkg/backup/cnpgrecovery"
	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

// The source schema must describe every exported receipt field and retain its
// pass constraints. Checking only selected properties can accept a schema whose
// required list silently omits an authorization or zero-residue fact.
func validatePostgreSQLHARecoveryEvidenceSchema(data []byte) error {
	expected, err := expectedPostgreSQLRecoveryEvidenceSchema()
	var received, contract any
	if err != nil || decodeOne(data, &received) != nil || decodeOne(expected, &contract) != nil || !reflect.DeepEqual(received, contract) {
		return errors.New("PostgreSQL recovery evidence schema contract is incomplete")
	}
	return nil
}

func expectedPostgreSQLRecoveryEvidenceSchema() ([]byte, error) {
	definitions := map[reflect.Type]string{
		reflect.TypeFor[cnpgrecovery.CleanupSweepEvidence]():     "cleanupSweep",
		reflect.TypeFor[cnpgrecovery.ConsistencyEvidence]():      "consistency",
		reflect.TypeFor[cnpgrecovery.RecoveryAccessBinding]():    "recoveryAccessBinding",
		reflect.TypeFor[cnpgrecovery.RecoveryAccessEvidence]():   "recoveryAccess",
		reflect.TypeFor[cnpgrecovery.CatalogEvidence]():          "catalog",
		reflect.TypeFor[cnpgrecovery.ApplicationAllowEvidence](): "applicationAllow",
		reflect.TypeFor[cnpgrecovery.ApplicationDenyEvidence]():  "applicationDeny",
		reflect.TypeFor[cnpgrecovery.ApplicationEvidence]():      "application",
		reflect.TypeFor[cnpgrecovery.LogicalClassEvidence]():     "logicalClass",
	}
	var build func(reflect.Type, string, string, bool) map[string]any
	build = func(value reflect.Type, name, parent string, expand bool) map[string]any {
		if reference, found := definitions[value]; found && !expand {
			return map[string]any{"$ref": "#/$defs/" + reference}
		}
		switch value.Kind() {
		case reflect.Struct:
			properties := map[string]any{}
			required := []string{}
			for index := 0; index < value.NumField(); index++ {
				field := value.Field(index)
				key := field.Tag.Get("json")
				property := build(field.Type, key, value.Name(), false)
				if key == "" || strings.Contains(key, ",") || property == nil {
					return nil
				}
				properties[key] = property
				required = append(required, key)
			}
			return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
		case reflect.Slice:
			var order []string
			selector := "operation"
			switch name {
			case "sweeps":
				return map[string]any{"type": "array", "minItems": 2, "maxItems": 2, "items": build(value.Elem(), "", parent, false)}
			case "classes":
				selector = "dataClass"
				order = []string{"portal-state", "orders", "support-tickets", "audit-events", "postgresql-cnpg"}
			case "allowed":
				order = []string{"documents-insert", "documents-read", "documents-update-cas", "documents-delete", "audit-insert", "audit-read"}
			case "denied":
				order = []string{"audit-update", "audit-delete", "schema-create", "migration-read", "migration-write", "document-truncate", "document-maintenance", "role-escalation"}
			default:
				return nil
			}
			prefix := []any{}
			for _, operation := range order {
				prefix = append(prefix, map[string]any{"allOf": []any{build(value.Elem(), "", parent, false), map[string]any{"properties": map[string]any{selector: map[string]any{"const": operation}}}}})
			}
			return map[string]any{"type": "array", "minItems": len(order), "maxItems": len(order), "items": false, "prefixItems": prefix}
		case reflect.Pointer:
			if name == "lastFailedAt" {
				return map[string]any{"type": "null"}
			}
			if name == "credentialExpiresAt" {
				return map[string]any{"type": []string{"string", "null"}, "format": "date-time"}
			}
		case reflect.Bool:
			denial := name == "containsCredentials" || name == "containsEndpoints" || name == "containsTenantData" ||
				name == "snapshotXidAssigned" || name == "markerXidBeforeAssigned" || name == "markerXidAfterAssigned"
			return map[string]any{"const": !denial}
		case reflect.Int, reflect.Int64:
			switch name {
			case "readyInstances", "expectedInstances", "affectedRows":
				return map[string]any{"const": 1}
			case "retentionDays", "objectLockMinimumDays":
				return map[string]any{"type": "integer", "minimum": 30}
			case "twoSweepQuietWindowSeconds":
				return map[string]any{"type": "integer", "minimum": 30, "maximum": 9223372036}
			case "bytes", "sourceLogicalBytes", "recoveredLogicalBytes", "sourceRowCount", "recoveredRowCount", "sourceBytes", "recoveredBytes":
				return map[string]any{"type": "integer", "minimum": 1}
			case "sourceRows", "recoveredRows":
				return map[string]any{"type": "integer", "minimum": 0}
			case "productionRouteCount", "snapshotActiveXidCount", "residualDocumentRows", "residualAuditRows",
				"recoveryNamespaceCount", "clusterCount", "accessObjectCount", "persistentVolumeClaimCount", "serviceCount", "routeCount":
				return map[string]any{"const": 0}
			}
		case reflect.String:
			if name == "identity" || name == "source" || name == "recovered" || strings.HasSuffix(name, "Identity") || strings.HasSuffix(name, "Digest") {
				return map[string]any{"$ref": "#/$defs/digest"}
			}
			if strings.HasSuffix(name, "At") || name == "firstRecoverabilityPoint" || name == "replayedThrough" {
				return map[string]any{"type": "string", "format": "date-time"}
			}
			constants := map[string]string{"schemaVersion": cnpgrecovery.EvidenceSchemaVersion, "status": "completed", "algorithm": "sha256",
				"projectionVersion": "cloudring-postgresql-logical-state/v1", "method": cnpgrecovery.ConsistencyMethod,
				"snapshotIsolation": "repeatable read", "contractVersion": transactionalstate.RecoveryContractSchemaVersion, "sqlState": "42501", "verdict": "pass"}
			if constant, found := constants[name]; found {
				return map[string]any{"const": constant}
			}
			switch name {
			case "sourceRevision":
				return map[string]any{"type": "string", "pattern": "^[0-9a-f]{40}$"}
			case "objectLockMode":
				return map[string]any{"enum": []string{"governance", "compliance"}}
			case "dataClass":
				return map[string]any{"enum": []string{"portal-state", "orders", "support-tickets", "audit-events", "postgresql-cnpg"}}
			case "operation":
				if parent == "ApplicationAllowEvidence" {
					return map[string]any{"enum": []string{"documents-insert", "documents-read", "documents-update-cas", "documents-delete", "audit-insert", "audit-read"}}
				}
				if parent == "ApplicationDenyEvidence" {
					return map[string]any{"enum": []string{"audit-update", "audit-delete", "schema-create", "migration-read", "migration-write", "document-truncate", "document-maintenance", "role-escalation"}}
				}
			}
		}
		return nil
	}
	schema := build(reflect.TypeFor[cnpgrecovery.Evidence](), "", "", true)
	if schema == nil {
		return nil, errors.New("PostgreSQL receipt field has no schema constraint")
	}
	defs := map[string]any{"digest": map[string]any{"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}}
	for value, name := range definitions {
		definition := build(value, "", "", true)
		if definition == nil {
			return nil, errors.New("PostgreSQL receipt field has no schema constraint")
		}
		defs[name] = definition
	}
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	schema["$id"] = "https://cloudring.org/schemas/postgresql-cnpg-offcell-recovery-evidence-v2.json"
	schema["title"] = "CloudRING PostgreSQL CNPG off-cell recovery evidence"
	schema["$defs"] = defs
	return json.MarshalIndent(schema, "", "  ")
}
