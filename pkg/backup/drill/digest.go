// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package drill

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func digest(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func PlanSHA256(plan Plan) string { return digest(plan) }

func ApprovalScopeSHA256(plan Plan) string {
	return digest(struct {
		SchemaVersion         string             `json:"schemaVersion"`
		PlanSHA256            string             `json:"planSha256"`
		OperationID           string             `json:"operationId"`
		ProofID               string             `json:"proofId"`
		InstallationID        string             `json:"installationId"`
		AcceptedPublicSHA     string             `json:"acceptedPublicSha"`
		AcceptedDownstreamSHA string             `json:"acceptedDownstreamSha"`
		ClusterSHA256         string             `json:"clusterSha256"`
		Adapter               ExecutableIdentity `json:"adapter"`
	}{"cloudring.backup-drill.approval-scope/v1", PlanSHA256(plan), plan.OperationID, plan.ProofID, plan.InstallationID,
		plan.AcceptedPublicSHA, plan.AcceptedDownstreamSHA, plan.ClusterIdentitySHA256, plan.Adapter})
}

func PreflightBindingSHA256(plan Plan, responseSHA256, evidenceRef, evidenceSHA256 string) string {
	return digest(struct {
		SchemaVersion           string `json:"schemaVersion"`
		ApprovalScopeSHA256     string `json:"approvalScopeSha256"`
		AdapterExecutableSHA256 string `json:"adapterExecutableSha256"`
		ResponseSHA256          string `json:"responseSha256"`
		EvidenceRef             string `json:"evidenceRef"`
		EvidenceSHA256          string `json:"evidenceSha256"`
	}{"cloudring.backup-drill.preflight-binding/v1", ApprovalScopeSHA256(plan), plan.Adapter.ExecutableSHA256, responseSHA256, evidenceRef, evidenceSHA256})
}

func ApprovalSHA256(report ApprovalReport) string { return digest(report) }

func ApprovalReportSHA256(report ApprovalReport) string {
	report.ReportSHA256 = ""
	return digest(report)
}

func AdapterRequestSHA256(request AdapterRequest) string {
	request.RequestSHA256 = ""
	return digest(request)
}

func AdapterResponseSHA256(response AdapterResponse) string {
	response.ResponseSHA256 = ""
	return digest(response)
}

func JournalEntrySHA256(entry JournalEntry) string {
	entry.EntrySHA256 = ""
	return digest(entry)
}

func ExecutionReceiptSHA256(receipt ExecutionReceipt) string {
	receipt.ReceiptSHA256 = ""
	return digest(receipt)
}
