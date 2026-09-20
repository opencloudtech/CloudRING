// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package roadmapprogram

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Measurement profiles are versioned acceptance inputs, never measurement
// results. Existing signed evidence carries the profile and workload digests.
type measurementProfiles struct {
	Version  string               `json:"version"`
	Status   string               `json:"status"`
	Contract string               `json:"contract"`
	Common   measurementCommon    `json:"common"`
	Profiles []measurementProfile `json:"profiles"`
	Human    humanMeasurement     `json:"human"`
	Scale    scaleMeasurement     `json:"scale"`
}

type latencyThresholds struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
}

type measurementCommon struct {
	WarmupSeconds                         uint              `json:"warmupSeconds"`
	BaselineSeconds                       uint              `json:"baselineSeconds"`
	QualificationSeconds                  uint              `json:"qualificationSeconds"`
	ProbeIntervalMilliseconds             uint              `json:"probeIntervalMilliseconds"`
	AvailabilityMinimumPercent            float64           `json:"availabilityMinimumPercent"`
	EligibleRequests                      string            `json:"eligibleRequests"`
	Exclusions                            string            `json:"exclusions"`
	PassFormula                           string            `json:"passFormula"`
	PercentileFormula                     string            `json:"percentileFormula"`
	DurableAcknowledgementMilliseconds    latencyThresholds `json:"durableAcknowledgementMilliseconds"`
	SingleFailureRPOSeconds               *uint             `json:"singleFailureRPOSeconds"`
	SingleFailureRTOSeconds               uint              `json:"singleFailureRTOSeconds"`
	OffCellRPOSeconds                     uint              `json:"offCellRPOSeconds"`
	OffCellRTOSeconds                     uint              `json:"offCellRTOSeconds"`
	CPUUtilizationMaximumPercent          float64           `json:"cpuUtilizationMaximumPercent"`
	MemoryUtilizationMaximumPercent       float64           `json:"memoryUtilizationMaximumPercent"`
	AbortUtilizationPercent               float64           `json:"abortUtilizationPercent"`
	OtherTenantP99RatioMaximum            float64           `json:"otherTenantP99RatioMaximum"`
	OtherTenantThroughputRatioMinimum     float64           `json:"otherTenantThroughputRatioMinimum"`
	ProviderLatencySeconds                []uint            `json:"providerLatencySeconds"`
	AmbiguousProviderResponsePercent      uint              `json:"ambiguousProviderResponsePercent"`
	ReconcileAfterProviderRecoverySeconds uint              `json:"reconcileAfterProviderRecoverySeconds"`
}

type measurementProfile struct {
	ID                                 string            `json:"id"`
	Goal                               string            `json:"goal"`
	Workload                           string            `json:"workload"`
	LatencyScope                       string            `json:"latencyScope"`
	SampleUnit                         string            `json:"sampleUnit"`
	MinimumSamples                     uint              `json:"minimumSamples"`
	MinimumLifecycleTrialsPerMethod    uint              `json:"minimumLifecycleTrialsPerMethod"`
	Concurrency                        uint              `json:"concurrency"`
	OfferedPerSecond                   float64           `json:"offeredPerSecond"`
	MinimumThroughputPerSecond         float64           `json:"minimumThroughputPerSecond"`
	SaturationSearchCeilingPerSecond   float64           `json:"saturationSearchCeilingPerSecond"`
	LatencyMilliseconds                latencyThresholds `json:"latencyMilliseconds"`
	QueueDepthMaximum                  uint              `json:"queueDepthMaximum"`
	OperationCompletionDeadlineSeconds uint              `json:"operationCompletionDeadlineSeconds"`
	FailureWorkload                    string            `json:"failureWorkload"`
}

type humanMeasurement struct {
	InstallAttentionMaximumMinutes  uint `json:"installAttentionMaximumMinutes"`
	DeveloperMaximumMinutes         uint `json:"developerMaximumMinutes"`
	DiagnosisStrictlyBelowSeconds   uint `json:"diagnosisStrictlyBelowSeconds"`
	HealthyToilMaximumMinutesPerDay uint `json:"healthyToilMaximumMinutesPerDay"`
	RepresentativeDays              uint `json:"representativeDays"`
	MinimumIndependentOperators     uint `json:"minimumIndependentOperators"`
	MinimumIndependentDevelopers    uint `json:"minimumIndependentDevelopers"`
}

type scaleMeasurement struct {
	TwoCellCapacityRatioMinimum       float64 `json:"twoCellCapacityRatioMinimum"`
	RecommendedHeadroomMinimumPercent float64 `json:"recommendedHeadroomMinimumPercent"`
	SaturationStepPercent             uint    `json:"saturationStepPercent"`
	SaturationStepSeconds             uint    `json:"saturationStepSeconds"`
}

func validLatencies(value latencyThresholds) bool {
	return value.P50 > 0 && value.P50 <= value.P95 && value.P95 <= value.P99
}

func validateMeasurementProfiles(root *os.Root, name string) error {
	data, err := readRegular(root, name)
	if err != nil {
		return err
	}
	if _, err := decodeStrictJSON(data); err != nil {
		return err
	}
	var profiles measurementProfiles
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profiles); err != nil {
		return err
	}
	if profiles.Version != "cloudring-qualification-v1" || profiles.Status != "acceptance-targets-not-measured" || profiles.Contract != "MEASUREMENT_CONTRACT.md" {
		return errors.New("version, non-measured status and measurement contract must be explicit")
	}
	c := profiles.Common
	if c.WarmupSeconds == 0 || c.BaselineSeconds < 1800 || c.QualificationSeconds < 86400 || c.ProbeIntervalMilliseconds == 0 || c.ProbeIntervalMilliseconds > 1000 || c.AvailabilityMinimumPercent < 99.95 || c.AvailabilityMinimumPercent > 100 {
		return errors.New("qualification windows, probes or availability weaken the measurement contract")
	}
	if c.EligibleRequests == "" || c.Exclusions == "" || c.PassFormula == "" || c.PercentileFormula == "" || !validLatencies(c.DurableAcknowledgementMilliseconds) || c.DurableAcknowledgementMilliseconds.P99 > 1000 {
		return errors.New("eligible requests, exclusions, formulas and durable acknowledgement thresholds are required")
	}
	if c.SingleFailureRPOSeconds == nil || *c.SingleFailureRPOSeconds != 0 || c.SingleFailureRTOSeconds == 0 || c.SingleFailureRTOSeconds > 300 || c.OffCellRPOSeconds == 0 || c.OffCellRPOSeconds > 900 || c.OffCellRTOSeconds == 0 || c.OffCellRTOSeconds > 3600 {
		return errors.New("RPO/RTO thresholds must preserve the single-failure and off-cell objectives")
	}
	if c.CPUUtilizationMaximumPercent <= 0 || c.CPUUtilizationMaximumPercent > 70 || c.MemoryUtilizationMaximumPercent <= 0 || c.MemoryUtilizationMaximumPercent > 80 || c.AbortUtilizationPercent <= c.MemoryUtilizationMaximumPercent || c.AbortUtilizationPercent > 95 || c.OtherTenantP99RatioMaximum < 1 || c.OtherTenantP99RatioMaximum > 1.2 || c.OtherTenantThroughputRatioMinimum < 0.8 || c.OtherTenantThroughputRatioMinimum > 1 {
		return errors.New("resource, abort and tenant fairness thresholds are missing or invalid")
	}
	if len(c.ProviderLatencySeconds) != 3 || c.ProviderLatencySeconds[0] != 1 || c.ProviderLatencySeconds[1] != 30 || c.ProviderLatencySeconds[2] != 120 || c.AmbiguousProviderResponsePercent != 10 || c.ReconcileAfterProviderRecoverySeconds == 0 || c.ReconcileAfterProviderRecoverySeconds > 300 {
		return errors.New("provider latency, ambiguity and reconciliation workload must be fixed")
	}
	required := map[string]string{"management-api": "G03", "lifecycle": "G09", "usage-billing": "G10", "portal-cli-agent": "G11", "network": "G12", "volume": "G13", "image-artifact": "G14", "compute": "G15", "kubernetes": "G16", "object": "G17", "backup": "G18", "access": "G19", "support": "G20", "external": "G21"}
	for _, profile := range profiles.Profiles {
		goal, exists := required[profile.ID]
		if !exists || goal != profile.Goal {
			return fmt.Errorf("duplicate, unknown or incorrectly owned profile %q", profile.ID)
		}
		delete(required, profile.ID)
		if profile.Workload == "" || profile.FailureWorkload == "" || profile.SampleUnit == "" || profile.MinimumLifecycleTrialsPerMethod < 3 || (profile.LatencyScope != "durable_ack" && profile.LatencyScope != "data_response" && profile.LatencyScope != "user_response") || profile.MinimumSamples < 1000 || profile.Concurrency == 0 || profile.OfferedPerSecond <= 0 || profile.MinimumThroughputPerSecond <= 0 || profile.MinimumThroughputPerSecond > profile.OfferedPerSecond || profile.SaturationSearchCeilingPerSecond < profile.OfferedPerSecond || !validLatencies(profile.LatencyMilliseconds) || profile.QueueDepthMaximum == 0 || profile.OperationCompletionDeadlineSeconds == 0 {
			return fmt.Errorf("%s: workload, sample size, latency, throughput, saturation, queue and completion thresholds must be fixed", profile.ID)
		}
		if (profile.ID == "lifecycle" || profile.ID == "external") && float64(profile.QueueDepthMaximum) < profile.OfferedPerSecond*float64(profile.OperationCompletionDeadlineSeconds) {
			return fmt.Errorf("%s: queue budget cannot contain offered operations through their bounded completion window", profile.ID)
		}
	}
	if len(required) != 0 {
		return errors.New("every management, lifecycle, billing, interaction and product profile is required")
	}
	h := profiles.Human
	if h.InstallAttentionMaximumMinutes == 0 || h.InstallAttentionMaximumMinutes > 120 || h.DeveloperMaximumMinutes == 0 || h.DeveloperMaximumMinutes > 120 || h.DiagnosisStrictlyBelowSeconds == 0 || h.DiagnosisStrictlyBelowSeconds > 300 || h.HealthyToilMaximumMinutesPerDay == 0 || h.HealthyToilMaximumMinutesPerDay > 30 || h.RepresentativeDays < 14 || h.MinimumIndependentOperators < 1 || h.MinimumIndependentDevelopers < 1 {
		return errors.New("human measurement thresholds must preserve independent install, developer, diagnosis and toil objectives")
	}
	s := profiles.Scale
	if s.TwoCellCapacityRatioMinimum < 1.7 || s.RecommendedHeadroomMinimumPercent < 30 || s.RecommendedHeadroomMinimumPercent >= 100 || s.SaturationStepPercent == 0 || s.SaturationStepPercent > 20 || s.SaturationStepSeconds < 300 {
		return errors.New("scale thresholds must preserve useful capacity, headroom and bounded saturation measurement")
	}
	return nil
}
