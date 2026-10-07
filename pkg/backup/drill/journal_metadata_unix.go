//go:build unix

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package drill

import (
	"math"
	"os"
	"syscall"
)

func protectedJournalFile(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	effectiveUID := os.Geteuid()
	if effectiveUID < 0 || uint64(effectiveUID) > math.MaxUint32 {
		return false
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && stat.Uid == uint32(effectiveUID) && stat.Nlink == 1
}
