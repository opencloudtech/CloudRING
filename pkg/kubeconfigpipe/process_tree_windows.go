//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package kubeconfigpipe

import "os/exec"

// Pipe-backed kubeconfig replay is already rejected on native Windows. Keep
// direct command execution buildable without making a containment claim.
func configureProcessTree(_ *exec.Cmd)     {}
func cleanupProcessTree(_ *exec.Cmd) error { return nil }
