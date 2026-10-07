//go:build !unix

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package drill

import (
	"errors"
	"os"
)

func lockJournalFile(_ *os.File) error   { return errors.New("journal locking is unsupported") }
func unlockJournalFile(_ *os.File) error { return nil }
