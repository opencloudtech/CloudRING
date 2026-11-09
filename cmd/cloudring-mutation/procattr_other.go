// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

//go:build !unix

package main

import "os/exec"

// ownProcessGroup keeps the default process handling where process groups
// are not available.
func ownProcessGroup(*exec.Cmd) {}
