// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/roadmapprogram"
)

const (
	exitSuccess = 0
	exitFailure = 1
	exitUsage   = 2

	invalidArgumentsMarker = "cloudring_roadmap_verify status=BLOCKED reason=invalid_arguments\n"
	validationFailedMarker = "cloudring_roadmap_verify status=BLOCKED reason=validation_failed\n"
	outputFailedMarker     = "cloudring_roadmap_verify status=BLOCKED reason=output_failed\n"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || arguments[0] != "verify" {
		return emitFailure(stderr, invalidArgumentsMarker, exitUsage)
	}

	flags := flag.NewFlagSet("cloudring-roadmap verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "./roadmap", "roadmap directory")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || strings.TrimSpace(*root) == "" {
		return emitFailure(stderr, invalidArgumentsMarker, exitUsage)
	}

	roadmap, err := roadmapprogram.Load(*root)
	if err != nil {
		return emitFailure(stderr, validationFailedMarker, exitFailure)
	}
	requirements := 0
	for _, goal := range roadmap.Spec.DeliveryOrder {
		requirements += len(goal.RequirementIDs)
	}
	marker := fmt.Sprintf("cloudring_roadmap_verified goals=%d requirements=%d\n", len(roadmap.Spec.DeliveryOrder), requirements)
	if !emit(stdout, marker) {
		return emitFailure(stderr, outputFailedMarker, exitFailure)
	}
	return exitSuccess
}

func emitFailure(stderr io.Writer, marker string, code int) int {
	if !emit(stderr, marker) {
		return exitFailure
	}
	return code
}

func emit(writer io.Writer, marker string) bool {
	written, err := io.WriteString(writer, marker)
	return err == nil && written == len(marker)
}
