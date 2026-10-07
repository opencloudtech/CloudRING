// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/opencloudtech/CloudRING/internal/privateartifact"
	"github.com/opencloudtech/CloudRING/pkg/resilience/oneserverloss"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "cloudring-resilience: operation failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, stdout io.Writer) error {
	if len(arguments) < 2 || arguments[0] != "one-server-loss" {
		return errors.New("one-server-loss command is required")
	}
	switch arguments[1] {
	case "observe":
		return runObserve(ctx, arguments[2:], stdout)
	case "verify":
		return runVerify(arguments[2:], stdout)
	default:
		return errors.New("unknown one-server-loss command")
	}
}

func runObserve(ctx context.Context, arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("one-server-loss observe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestPath := flags.String("request", "", "private observation request JSON")
	outputPath := flags.String("output", "", "new private receipt JSON")
	readyMarkerPath := flags.String("ready-marker", "", "new private ready-for-fault marker JSON")
	kubectlPath := flags.String("kubectl", "", "kubectl executable path")
	probeAdapterPath := flags.String("probe-adapter", "", "absolute data-probe adapter executable path")
	kubeconfigFD := flags.Int("kubeconfig-fd", -1, "pipe descriptor containing kubeconfig")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *requestPath == "" || *outputPath == "" || *readyMarkerPath == "" ||
		*kubectlPath == "" || *probeAdapterPath == "" || *kubeconfigFD < 3 || samePath(*outputPath, *readyMarkerPath) {
		return errors.New("invalid one-server-loss observe arguments")
	}
	if err := ensureNewDestinations(*outputPath, *readyMarkerPath); err != nil {
		return err
	}
	var request oneserverloss.Request
	if err := readExactJSON(*requestPath, &request); err != nil {
		return errors.New("read one-server-loss request")
	}
	reader, err := newKubectlReader(*kubectlPath, *kubeconfigFD)
	if err != nil {
		return err
	}
	defer reader.Close()
	probe, err := newExecProbe(*probeAdapterPath, reader.replay)
	if err != nil {
		return err
	}
	defer probe.Close()
	barrier := fileReadyBarrier{path: *readyMarkerPath}
	receipt, err := oneserverloss.Observe(ctx, reader, probe, barrier, request, oneserverloss.SystemClock())
	if err != nil {
		return err
	}
	if err := privateartifact.WriteNewJSON(*outputPath, receipt); err != nil {
		return errors.New("publish one-server-loss receipt")
	}
	_, _ = fmt.Fprintln(stdout, "status=one_server_loss_receipt_written")
	return nil
}

func runVerify(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("one-server-loss verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	receiptPath := flags.String("receipt", "", "private receipt JSON")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *receiptPath == "" {
		return errors.New("invalid one-server-loss verify arguments")
	}
	var receipt oneserverloss.Receipt
	if err := readExactJSON(*receiptPath, &receipt); err != nil {
		return errors.New("read one-server-loss receipt")
	}
	if err := oneserverloss.ValidateReceipt(&receipt); err != nil {
		return errors.New("one-server-loss receipt is invalid")
	}
	_, _ = fmt.Fprintln(stdout, "status=one_server_loss_receipt_verified")
	return nil
}

type fileReadyBarrier struct{ path string }

func (barrier fileReadyBarrier) ReadyForFault(ctx context.Context, marker oneserverloss.ReadyMarker) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := oneserverloss.ValidateReadyMarker(marker); err != nil {
		return err
	}
	return privateartifact.WriteNewJSON(barrier.path, marker)
}

func readExactJSON(path string, destination any) error {
	return privateartifact.ReadJSON(path, destination)
}

func ensureNewDestinations(paths ...string) error {
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(filepath.Clean(path))
		if err != nil || absolute == string(filepath.Separator) {
			return errors.New("private artifact destination is invalid")
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
		if err != nil {
			return errors.New("private artifact directory is invalid")
		}
		destination := filepath.Join(parent, filepath.Base(absolute))
		if _, duplicate := seen[destination]; duplicate {
			return errors.New("private artifact destinations overlap")
		}
		seen[destination] = struct{}{}
		if _, err := os.Lstat(destination); err == nil || !os.IsNotExist(err) {
			return errors.New("private artifact destination is unavailable")
		}
	}
	return nil
}

func samePath(left, right string) bool {
	leftAbsolute, leftErr := filepath.Abs(filepath.Clean(left))
	rightAbsolute, rightErr := filepath.Abs(filepath.Clean(right))
	return leftErr != nil || rightErr != nil || leftAbsolute == rightAbsolute
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
