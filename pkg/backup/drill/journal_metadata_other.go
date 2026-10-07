//go:build !unix

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package drill

import "os"

// Native Windows is not a supported drill runtime. Keep builds portable while
// failing closed on anything except the regular owner-mode artifact shape.
func protectedJournalFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600
}
