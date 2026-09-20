// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/opencloudtech/CloudRING/pkg/devinstall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(devinstall.RunCLI(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
