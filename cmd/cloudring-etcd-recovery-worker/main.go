// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/backup/etcdrecovery"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) != 1 {
		receipt := etcdrecovery.InitializationFailureReceipt(time.Now().UTC())
		if err := etcdrecovery.WriteReceipt(etcdrecovery.DefaultReceiptPath, receipt); err != nil {
			fmt.Fprintln(os.Stderr, "cloudring_etcd_recovery_worker_failed")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "cloudring_etcd_recovery_worker_failed")
		os.Exit(2)
	}
	receipt, err := etcdrecovery.RunDefault(ctx)
	if err != nil {
		if writeErr := etcdrecovery.WriteReceipt(etcdrecovery.DefaultReceiptPath, receipt); writeErr != nil {
			fmt.Fprintln(os.Stderr, "cloudring_etcd_recovery_worker_failed")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "cloudring_etcd_recovery_worker_failed")
		os.Exit(1)
	}
	if err := etcdrecovery.WriteReceipt(etcdrecovery.DefaultReceiptPath, receipt); err != nil {
		fmt.Fprintln(os.Stderr, "cloudring_etcd_recovery_worker_failed")
		os.Exit(1)
	}
}
