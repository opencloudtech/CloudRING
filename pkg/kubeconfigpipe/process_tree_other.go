//go:build !unix && !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package kubeconfigpipe

import "os/exec"

func configureProcessTree(_ *exec.Cmd)     {}
func cleanupProcessTree(_ *exec.Cmd) error { return nil }
