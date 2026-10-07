// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package ocs

func validBillingConnector() BillingConnector {
	return BillingConnector{
		APIVersion: APIVersion,
		Kind:       "BillingConnector",
		Metadata: Metadata{
			Name:        "object-storage-billing",
			DisplayName: "Object Storage Billing",
			Owner:       "storage-team",
			Version:     "v0.1.0",
		},
		Meters: []UsageMeter{{Name: "stored_bytes", Unit: "byte-hour"}},
		CostMeters: []CostMeter{{
			Name:        "storage_gib_month",
			Currency:    "USD",
			UnitPrice:   "0.00-example",
			MeterRef:    "stored_bytes",
			EvidenceRef: "evidence.object-storage.cost-meter",
		}},
		Events: []BillingEvent{{
			Name:           "storage-usage-recorded",
			Meter:          "stored_bytes",
			Idempotent:     true,
			IdempotencyKey: "usageEvent.id",
			EntitlementRef: "catalog.plan.standard",
			Attribution:    "tenant.project.subscription",
			ReplayPolicy:   "dedupe-by-idempotency-key",
		}},
	}
}
