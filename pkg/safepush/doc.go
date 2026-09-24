// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Package safepush provides deterministic checks over CI observations.
//
// VerifyChecks is a pure consistency check, not an enforcement boundary or a
// complete authorization decision. Its inputs cannot prove their own origin,
// freshness, or completeness. In particular, a source identity, caller assertion,
// or signature alone does not establish that a workflow actually ran.
//
// The native adapter must read the trusted required-job policy and complete,
// paginated run/job records from the owning CI service. It must verify the
// immutable workflow source and execution bindings before constructing source
// identities, and resolve run attempts without choosing an older green result.
// It must include every job in that scope, except exclusions explicitly permitted
// by the trusted policy. Branch enforcement, review approval, bypass authority,
// and revalidation when the candidate or target changes remain outside this
// helper.
package safepush
