//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package kubeconfigpipe

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func duplicateFD(fd int) (*os.File, error) {
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, errors.New("duplicate pipe-backed kubeconfig descriptor")
	}
	file := os.NewFile(uintptr(duplicate), "cloudring-kubeconfig-pipe")
	if file == nil {
		_ = unix.Close(duplicate)
		return nil, errors.New("open pipe-backed kubeconfig")
	}
	return file, nil
}
