// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

//go:build !linux

package etcdrecovery

import (
	"context"
	"errors"
	"time"
)

func openPinnedTool(context.Context, string, string, time.Duration) (toolRunner, error) {
	return nil, errors.New("offline recovery tool execution requires Linux")
}
