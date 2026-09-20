//go:build !linux && !darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"io/fs"
	"os"
)

func guestOwnedFile(_ fs.FileInfo, _ fs.FileMode) bool { return false }

func guestInspectDatabaseDirectory(_ *os.Root, _ string) (guestDirectoryIdentity, bool, error) {
	return guestDirectoryIdentity{}, false, ErrConflict
}
