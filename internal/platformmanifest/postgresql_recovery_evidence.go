// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package platformmanifest

import (
	"io"

	"github.com/opencloudtech/CloudRING/pkg/backup/cnpgrecovery"
)

// VerifyPostgreSQLRecoveryEvidence preserves the platform-manifest verifier
// API while requiring the portable v2 evidence contract. Historical v1 receipts
// do not establish the stronger consistency and authorization requirements.
func VerifyPostgreSQLRecoveryEvidence(reader io.Reader) error {
	return cnpgrecovery.VerifyEvidence(reader)
}

// VerifyPostgreSQLRecoveryEvidenceForRevision also binds the receipt to the
// accepted public-core revision selected by the caller.
func VerifyPostgreSQLRecoveryEvidenceForRevision(reader io.Reader, acceptedPublicSHA string) error {
	return cnpgrecovery.VerifyEvidenceForRevision(reader, acceptedPublicSHA)
}
