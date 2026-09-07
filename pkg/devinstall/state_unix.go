//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func ownedDirectory(info fs.FileInfo, private bool) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || private && info.Mode().Perm() != 0o700 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(stat.Uid) == int64(os.Geteuid())
}

func ownedRegularFile(info, root fs.FileInfo) bool {
	if info == nil || root == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	rootStat, rootOK := root.Sys().(*syscall.Stat_t)
	return ok && rootOK && int64(stat.Uid) == int64(os.Geteuid()) && stat.Dev == rootStat.Dev && stat.Nlink == 1
}

func lockState(file *os.File) error {
	if file == nil {
		return ErrConflict
	}
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func stateNoFollowFlag() int { return unix.O_NOFOLLOW }
