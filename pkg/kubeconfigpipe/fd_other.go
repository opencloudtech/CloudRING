//go:build !linux && !darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package kubeconfigpipe

import (
	"errors"
	"os"
)

func duplicateFD(_ int) (*os.File, error) {
	return nil, errors.New("pipe-backed kubeconfig runtime is unsupported")
}
