//go:build unix

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package drill

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockJournalFile(file *os.File) error   { return unix.Flock(int(file.Fd()), unix.LOCK_EX) }
func unlockJournalFile(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }
