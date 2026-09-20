//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"io/fs"
	"os"
	"syscall"
)

func guestOwnedFile(info fs.FileInfo, mode fs.FileMode) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(stat.Uid) == int64(os.Geteuid()) && stat.Nlink == 1
}

func guestInspectDatabaseDirectory(root *os.Root, name string) (guestDirectoryIdentity, bool, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 && info.Mode().Perm() != 0o770 || info.Mode()&(os.ModeSetuid|os.ModeSticky) != 0 {
		return guestDirectoryIdentity{}, false, ErrConflict
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev < 0 || !(stat.Uid == 999 && stat.Gid == 999 || stat.Uid == 0 && stat.Gid == 0 && info.Mode().Perm() == 0o700) {
		return guestDirectoryIdentity{}, false, ErrConflict
	}
	return guestDirectoryIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}, stat.Uid == 0, nil
}
