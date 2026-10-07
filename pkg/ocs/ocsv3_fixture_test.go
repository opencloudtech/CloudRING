// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package ocs

func validDistributionProfile() DistributionProfile {
	return DistributionProfile{
		DeploymentProfiles:    []string{"self-hosted", "provider-managed", "edge-zone"},
		Channels:              []string{"open-source", "enterprise-marketplace"},
		InfrastructureTargets: []string{"kubernetes", "private-cloud", "public-cloud", "edge"},
		UpdatePolicyRef:       "updates.object-storage.compatibility-reviewed",
	}
}

func validFederationProfile() FederationProfile {
	return FederationProfile{
		Applicability:          ApplicabilitySupported,
		Modes:                  []string{"standalone", "connected", "federated"},
		MessageBusRef:          "federation.bus.ocsv3.events",
		CrossProviderScenarios: []string{"replication", "migration", "support-handoff"},
		PortabilityPolicyRef:   "policy.object-storage.no-provider-lock-in",
	}
}

func validCommercialProfile() CommercialProfile {
	return CommercialProfile{
		Applicability:           ApplicabilitySupported,
		Roles:                   []string{"vendor", "provider", "reseller"},
		RevenueModel:            "metered-usage-with-revenue-share",
		LicenseRef:              "license.object-storage.enterprise-marketplace",
		ExpiryBehavior:          "service-keeps-running-updates-stop-except-critical-fixes",
		SupportRef:              "support.object-storage.provider-handoff",
		ServiceProvenance:       "first-party-provider-managed",
		ResponsibilityMatrixRef: "responsibility.object-storage.provider-and-partner",
		ContinuityPlanRef:       "continuity.object-storage.dr-restorable",
	}
}
