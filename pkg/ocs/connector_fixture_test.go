// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package ocs

func validConnectorPackage() ConnectorPackage {
	return ConnectorPackage{
		APIVersion: APIVersion,
		Kind:       "ConnectorPackage",
		Metadata: Metadata{
			Name:        "object-storage-package",
			DisplayName: "Object Storage Package",
			Owner:       "storage-team",
			Version:     "v0.1.0",
		},
		Service: validServiceConnector(),
		Billing: validBillingConnector(),
		Catalog: CatalogPublication{
			ServiceClass: "object-storage",
			Visibility:   "tenant",
			Portability:  "export-import",
			Plans: []CatalogPlan{{
				Name:        "standard",
				DisplayName: "Standard Object Storage",
				BillingMode: "metered",
				QuotaRef:    "quota.object-storage.standard",
			}},
		},
		Configuration: ConfigurationSchema{
			SchemaRef: "schemas/object-storage.v1alpha1.json",
			Version:   "v1alpha1",
		},
		Readiness: []ReadinessCheck{{
			Name:        "bucket-controller-ready",
			Type:        "kubernetes-condition",
			Target:      "ObjectBucket.status.conditions",
			Condition:   "Ready",
			EvidenceRef: "support.diagnostics.bucket-status",
		}},
		TenantAccess: TenantAccessPolicy{
			Scope:          "project",
			EntitlementRef: "catalog.plan.standard",
			Entitlements: []TenantEntitlement{{
				Name:  "standard-plan",
				Ref:   "catalog.plan.standard",
				Scope: "project",
			}},
			Permissions: []string{"object-storage.read", "object-storage.write"},
		},
		Durability: DurabilityProfile{
			StateClass:        "stateful",
			DataClasses:       []string{"tenant-object-data", "usage-events"},
			BackupPolicyRef:   "backup.object-storage.standard",
			RecoveryObjective: "restore-test-required-before-production",
			RecoveryEvidence: []EvidenceRef{{
				Name: "restore-drill",
				Type: "runbook-evidence",
				Ref:  "evidence.object-storage.restore",
			}},
		},
		Distribution: validDistributionProfile(),
		Federation:   validFederationProfile(),
		Commercial:   validCommercialProfile(),
	}
}

func validServiceConnector() ServiceConnector {
	return ServiceConnector{
		APIVersion: APIVersion,
		Kind:       "ServiceConnector",
		Metadata: Metadata{
			Name:        "object-storage",
			DisplayName: "Object Storage",
			Owner:       "storage-team",
			Version:     "v0.1.0",
		},
		Spec: ServiceSpec{
			ExecutionProfile: ExecutionProfileLocal,
			ProductAPI: ProductAPIContract{
				Ref:      "service.api.object-storage.v1alpha1",
				Version:  "v1alpha1",
				Protocol: "https-json",
			},
			Capabilities: []Capability{{
				Class:       "object-storage",
				Name:        "bucket",
				Description: "Tenant-scoped object storage bucket lifecycle",
			}},
			Dependencies: []Dependency{{
				ID:                     "storage-backend",
				CapabilityClass:        "object-storage",
				Role:                   "data-plane",
				Portability:            "export-import",
				ProductAPIRef:          "service.api.storage-backend.v1",
				VersionRange:           ">=1.0.0,<2.0.0",
				CompatibilityPolicyRef: "policy.compatibility.storage-backend",
			}},
			Lifecycle: []LifecycleAction{{
				Name:           "provision",
				Applicability:  ApplicabilitySupported,
				Verb:           "Apply",
				Idempotent:     true,
				IdempotencyKey: "metadata.uid",
			}, {
				Name:          "hold",
				Applicability: ApplicabilityNotApplicable,
				Reason:        "object storage buckets remain available until deprovisioned",
			}, {
				Name:          "resume",
				Applicability: ApplicabilityNotApplicable,
				Reason:        "hold is not supported",
			}, {
				Name:          "resize",
				Applicability: ApplicabilityNotApplicable,
				Reason:        "capacity follows plan and quota changes",
			}, {
				Name:           "deprovision",
				Applicability:  ApplicabilitySupported,
				Verb:           "Delete",
				Idempotent:     true,
				IdempotencyKey: "delete.request.id",
			}, {
				Name:           "rotateAccessKey",
				Applicability:  ApplicabilitySupported,
				Verb:           "Rotate",
				Idempotent:     true,
				IdempotencyKey: "rotation.request.id",
				RollbackRef:    "support.restorePreviousKey",
			}, {
				Name:           "export",
				Applicability:  ApplicabilitySupported,
				Verb:           "Export",
				Idempotent:     true,
				IdempotencyKey: "export.request.id",
			}},
			Automation: []AutomationTask{{
				Name:        "rotate-access-key",
				Description: "Rotate tenant access material through the connector",
				ActionRef:   "lifecycle.rotateAccessKey",
			}},
			UsageMeters: []UsageMeter{{Name: "stored_bytes", Unit: "byte-hour"}},
			Billing: BillingProfile{
				Applicability: ApplicabilitySupported,
				ConnectorRef:  "object-storage-billing",
				Meters:        []UsageMeter{{Name: "stored_bytes", Unit: "byte-hour"}},
			},
			PortalModules: []PortalModule{{
				Name:        "bucket-overview",
				Slot:        "service.detail",
				Route:       "/services/object-storage/buckets",
				APIRef:      "service.api.object-storage.buckets",
				HostRef:     "ui.object-storage.host",
				MountRef:    "mount.object-storage.bucket-overview",
				Permissions: []string{"object-storage.read"},
			}},
			UI: UIExtensionManifest{
				EmbedRef:         "ui.object-storage.bundle",
				ContextSchemaRef: "schemas/object-storage-ui-context.v1alpha1.json",
				HostAuthority:    []string{"navigation", "identity", "policy"},
				ExtensionActions: []string{"bucket.create", "bucket.delete"},
				ModuleHost: MicrofrontendHostContract{
					Host:            "cloudring-provider-portal",
					Runtime:         "module-federation",
					MountRef:        "mount.object-storage.bucket-overview",
					VersionRange:    ">=0.1.0 <1.0.0",
					SignatureRef:    "evidence.object-storage.ui.signature",
					IntegrityRef:    "evidence.object-storage.ui.integrity",
					Sandbox:         "tenant-iam-context",
					AllowedEvents:   []string{"bucket.create.requested", "bucket.delete.requested"},
					RequiredContext: []string{"tenant", "project", "iam.subject", "locale", "theme"},
				},
				Evidence: []EvidenceRef{{
					Name: "ui-host-shell-certification",
					Type: "certification-evidence",
					Ref:  "evidence.object-storage.ui.host-shell",
				}},
			},
			AnalyticsEvents: []AnalyticsEvent{{
				Name:        "object-storage.bucket.create.submitted",
				Trigger:     "portal-module-action",
				Subject:     "tenant.project.service-order",
				Properties:  []string{"tenantId", "projectId", "plan", "region", "result"},
				EvidenceRef: "evidence.object-storage.analytics",
			}},
			KubernetesBindings: []KubernetesBinding{{
				Group:      "storage.cloudring.io",
				Version:    "v1alpha1",
				Kind:       "ObjectBucket",
				Plural:     "objectbuckets",
				Scope:      "Namespaced",
				CRDRef:     "crd.objectbuckets.storage.cloudring.io",
				StatusPath: "status.conditions",
				Condition:  "Ready",
			}},
			GatewayRoutes: []GatewayRoute{{
				Name:        "object-storage-api",
				ParentRef:   "gateway.platform.service-api",
				Hostnames:   []string{"object-storage.services.example"},
				Rules:       []string{"tenant-scoped-bucket-api"},
				EvidenceRef: "evidence.object-storage.gateway-route",
			}},
			Secrets: SecretBoundary{
				WorkloadIdentityRef: "workloadidentity.object-storage-controller",
				SecretRefs: []SecretRef{{
					Name:     "s3-credential-reference",
					Ref:      "secretref.object-storage.access-key",
					Purpose:  "tenant data-plane access",
					Rotation: "operator-initiated",
				}},
			},
			Policies: []PolicyRule{{
				Name:        "tenant-data-residency",
				Class:       "data-residency",
				DecisionRef: "policy.object-storage.residency",
				EvidenceRef: "evidence.object-storage.policy",
			}},
			DataLifecycle: DataLifecycle{
				Export: DataLifecycleAction{
					ActionRef:   "lifecycle.export",
					Format:      "ocs-portable-archive",
					EvidenceRef: "evidence.object-storage.export",
				},
				Delete: DataLifecycleAction{
					ActionRef:   "lifecycle.deprovision",
					Format:      "tenant-object-delete-receipt",
					EvidenceRef: "evidence.object-storage.delete",
				},
			},
			States: []ServiceState{{
				Name:        "degraded",
				Reason:      "backend capability unavailable",
				UserVisible: true,
				EvidenceRef: "evidence.object-storage.degraded",
				Remediation: "retry after capability recovery or export data",
			}, {
				Name:        "blocked",
				Reason:      "policy denial or missing entitlement",
				UserVisible: true,
				EvidenceRef: "evidence.object-storage.blocked",
				Remediation: "resolve policy or entitlement before retry",
			}},
			Support: SupportProfile{
				Owner:       "storage-team",
				Escalation:  "provider-support",
				Diagnostics: []string{"bucket-status", "usage-ingestion-status"},
				DocsRef:     "docs/services/object-storage.md",
				Evidence: []EvidenceRef{{
					Name: "support-diagnostics",
					Type: "support-evidence",
					Ref:  "evidence.object-storage.support-diagnostics",
				}},
			},
			EvidenceBundles: []EvidenceBundle{{
				Name:       "ocsv3-support-bundle",
				Owner:      "storage-team",
				Claim:      "support diagnostics, UI certification, policy, and data lifecycle evidence are linked",
				Freshness:  "review-before-publication",
				Redaction:  "support-safe-summary-only",
				Evidence:   []EvidenceRef{{Name: "support-diagnostics", Type: "support-evidence", Ref: "evidence.object-storage.support-diagnostics"}},
				NonClaims:  []string{"does not prove provider production readiness"},
				ReviewPath: "support.owner.review",
			}},
		},
	}
}
