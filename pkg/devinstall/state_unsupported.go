//go:build !linux && !darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"io/fs"
	"os"
)

func ownedDirectory(_ fs.FileInfo, _ bool) bool { return false }
func ownedRegularFile(_, _ fs.FileInfo) bool    { return false }
func lockState(_ *os.File) error                { return ErrConflict }
func stateNoFollowFlag() int                    { return 0 }
