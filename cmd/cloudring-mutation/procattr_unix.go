// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup starts cmd in a new process group and makes cancellation
// stop the whole group, including the test binary go test started.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
