// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package etcdrecovery

import (
	"os"
	"syscall"
)

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(stat.Uid) == int64(os.Geteuid())
}

func ownedByCurrentOrRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || int64(stat.Uid) == int64(os.Geteuid()))
}

func workspaceRegularSafe(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && info.Mode().Perm()&0o022 == 0
}
