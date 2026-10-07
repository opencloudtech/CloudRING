// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/kubeadm"
	"github.com/opencloudtech/CloudRING/pkg/resilience/oneserverloss"
	"github.com/opencloudtech/CloudRING/pkg/siteprofile"
)

const (
	exitSuccess  = 0
	exitFailure  = 1
	exitUsage    = 2
	exitBlocked  = 3
	exitInternal = 4
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "preflight", "plan":
		return runSiteProfile(args[0], args[1:], stdin, stdout, stderr)
	case "render-kubeadm":
		return runKubeadmRender(args[1:], stdin, stdout, stderr)
	case "verify-kubeadm":
		return runKubeadmVerify(args[1:], stdin, stdout, stderr)
	default:
		printUsage(stderr)
		return exitUsage
	}
}

func runSiteProfile(command string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profilePath := flags.String("profile", "-", "provider site profile path or - for stdin")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		printUsage(stderr)
		return exitUsage
	}
	reader, closeReader, err := openProfile(*profilePath, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "provider site profile unavailable")
		return exitFailure
	}
	defer closeReader()
	profile, err := siteprofile.Parse(reader)
	if err != nil {
		fmt.Fprintln(stderr, "provider site profile invalid")
		return exitFailure
	}
	if command == "preflight" {
		report := siteprofile.Validate(profile)
		if err := encodeJSON(stdout, report); err != nil {
			fmt.Fprintln(stderr, "encode provider site preflight")
			return exitInternal
		}
		if report.Status != "ready" {
			return exitFailure
		}
		return exitSuccess
	}
	plan, err := siteprofile.BuildPlan(profile)
	if err != nil {
		fmt.Fprintln(stderr, "provider site plan blocked")
		return exitFailure
	}
	if err := encodeJSON(stdout, plan); err != nil {
		fmt.Fprintln(stderr, "encode provider site plan")
		return exitInternal
	}
	return exitSuccess
}

func runKubeadmRender(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	specPath, ok := parseInputPath("render-kubeadm", "spec", args, stderr)
	if !ok {
		return exitUsage
	}
	var spec kubeadm.BootstrapSpec
	if err := decodeExactInput(specPath, stdin, &spec); err != nil {
		fmt.Fprintln(stderr, "kubeadm bootstrap spec invalid")
		return exitFailure
	}
	bundle, err := kubeadm.RenderStackedEtcdDualStackConfig(spec)
	if err != nil {
		fmt.Fprintln(stderr, "kubeadm bootstrap spec blocked")
		return exitFailure
	}
	if err := encodeJSON(stdout, bundle); err != nil {
		fmt.Fprintln(stderr, "encode kubeadm bootstrap bundle")
		return exitInternal
	}
	return exitSuccess
}

func runKubeadmVerify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify-kubeadm", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inventoryPath := flags.String("inventory", "-", "stand inventory JSON path or - for stdin")
	receiptPath := flags.String("one-server-loss-receipt", "", "one-server-loss receipt JSON path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 ||
		strings.TrimSpace(*inventoryPath) == "" ||
		(*inventoryPath == "-" && *receiptPath == "-") {
		printUsage(stderr)
		return exitUsage
	}
	var inventory kubeadm.StandInventory
	if err := decodeExactInput(*inventoryPath, stdin, &inventory); err != nil {
		fmt.Fprintln(stderr, "kubeadm stand inventory invalid")
		return exitFailure
	}
	var receipt *oneserverloss.Receipt
	if strings.TrimSpace(*receiptPath) != "" {
		receipt = &oneserverloss.Receipt{}
		if err := decodeExactInput(*receiptPath, stdin, receipt); err != nil {
			fmt.Fprintln(stderr, "one-server-loss receipt invalid")
			return exitFailure
		}
	}
	report, err := kubeadm.VerifyUpstreamStand(inventory, receipt)
	if err != nil && !errors.Is(err, kubeadm.ErrStandBlocked) {
		fmt.Fprintln(stderr, "kubeadm stand verification failed")
		return exitFailure
	}
	if encodeErr := encodeJSON(stdout, report); encodeErr != nil {
		fmt.Fprintln(stderr, "encode kubeadm stand report")
		return exitInternal
	}
	if errors.Is(err, kubeadm.ErrStandBlocked) {
		return exitBlocked
	}
	return exitSuccess
}

func parseInputPath(command, flagName string, args []string, stderr io.Writer) (string, bool) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String(flagName, "-", "JSON input path or - for stdin")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || strings.TrimSpace(*path) == "" {
		printUsage(stderr)
		return "", false
	}
	return *path, true
}

func decodeExactInput(path string, stdin io.Reader, destination any) error {
	reader, closeReader, err := openProfile(path, stdin)
	if err != nil {
		return err
	}
	defer closeReader()
	payload, err := strictjson.Read(reader)
	if err != nil {
		return err
	}
	defer clear(payload)
	return strictjson.DecodeExact(payload, destination)
}

func encodeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: cloudring-site preflight|plan --profile <path|->")
	fmt.Fprintln(writer, "       cloudring-site render-kubeadm --spec <path|->")
	fmt.Fprintln(writer, "       cloudring-site verify-kubeadm --inventory <path|-> --one-server-loss-receipt <path|->")
}

func openProfile(path string, stdin io.Reader) (io.Reader, func(), error) {
	if strings.TrimSpace(path) == "-" {
		if stdin == nil {
			return nil, func() {}, siteprofile.ErrInvalidProfile
		}
		return stdin, func() {}, nil
	}
	// #nosec G304 G703 -- the local operator explicitly selects the bounded, strict profile input.
	file, err := os.Open(path)
	if err != nil {
		return nil, func() {}, err
	}
	return file, func() { _ = file.Close() }, nil
}
