// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openProtectedOperatorFile(path string, ownerOnly bool) (*os.File, error) {
	directory := filepath.Dir(path)
	name := filepath.Base(path)
	// #nosec G304 -- the explicit operator directory is opened without
	// following its final symlink; the file is opened relative to that handle.
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open operator input directory")
	}
	defer unix.Close(directoryFD)
	fileFD, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("open protected operator input")
	}
	file := os.NewFile(uintptr(fileFD), name)
	if file == nil {
		_ = unix.Close(fileFD)
		return nil, errors.New("adopt protected operator input")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || ownerOnly && info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, errors.New("operator input must be a protected regular file")
	}
	return file, nil
}
