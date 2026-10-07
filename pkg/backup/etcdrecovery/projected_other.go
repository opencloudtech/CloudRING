// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package etcdrecovery

import (
	"context"
	"errors"
)

func readProjectedBytes(string, string, []string, int64) ([]byte, error) {
	return nil, errors.New("projected recovery inputs are unsupported")
}
func readProjectedBytesContext(context.Context, string, string, []string, int64) ([]byte, error) {
	return nil, errors.New("projected recovery inputs are unsupported")
}
func readProjectedSetContext(context.Context, string, []string, []string, int64) (map[string][]byte, error) {
	return nil, errors.New("projected recovery inputs are unsupported")
}
