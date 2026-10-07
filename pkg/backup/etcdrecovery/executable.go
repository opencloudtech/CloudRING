// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package etcdrecovery

import (
	"context"
	"errors"
	"os"
)

func runningExecutableSHA256(ctx context.Context) (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", errors.New("resolve running recovery executable")
	}
	executable, err := openProtectedFile(path, maximumToolBytes, trustedExecutable)
	if err != nil {
		return "", errors.New("open running recovery executable")
	}
	defer executable.Close()
	digest, _, err := executable.DigestContext(ctx)
	if err != nil {
		return "", errors.New("digest running recovery executable")
	}
	return digest, nil
}
