// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/httpsecurity"
)

const (
	exitPassed  = 0
	exitUsage   = 1
	exitBlocked = 2
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 15 * time.Second}
	os.Exit(run(ctx, os.Args[1:], client, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, client *http.Client, stdout, stderr io.Writer) int {
	target, mode, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	report, err := httpsecurity.Audit(ctx, client, target, mode)
	if err != nil {
		if errors.Is(err, httpsecurity.ErrInvalidConfiguration) {
			fmt.Fprintln(stderr, httpsecurity.ErrInvalidConfiguration)
		} else {
			fmt.Fprintln(stderr, "HTTP security audit unavailable")
		}
		return exitUsage
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(stderr, "encode HTTP security audit report")
		return exitUsage
	}
	if !report.Passed {
		fmt.Fprintln(stderr, "HTTP security audit blocked")
		return exitBlocked
	}
	return exitPassed
}

func parseArgs(args []string) (httpsecurity.Target, httpsecurity.Mode, error) {
	if len(args) == 0 || args[0] != "check" {
		return httpsecurity.Target{}, "", usageError()
	}
	flags := flag.NewFlagSet("cloudring-httpcheck check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	targetID := flags.String("target-id", "", "safe identifier included in the report")
	targetURL := flags.String("url", "", "canonical HTTPS URL to inspect")
	modeValue := flags.String("mode", "", "promotion mode: canary or steady")
	surfaceValue := flags.String("surface", "", "surface policy: browser or api")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return httpsecurity.Target{}, "", usageError()
	}
	mode := httpsecurity.Mode(*modeValue)
	surface := httpsecurity.Surface(*surfaceValue)
	if *targetID == "" || *targetURL == "" || !validMode(mode) || !validSurface(surface) {
		return httpsecurity.Target{}, "", usageError()
	}
	return httpsecurity.Target{ID: *targetID, URL: *targetURL, Surface: surface}, mode, nil
}

func validMode(mode httpsecurity.Mode) bool {
	return mode == httpsecurity.ModeCanary || mode == httpsecurity.ModeSteady
}

func validSurface(surface httpsecurity.Surface) bool {
	return surface == httpsecurity.SurfaceBrowser || surface == httpsecurity.SurfaceAPI
}

func usageError() error {
	return errors.New("usage: cloudring-httpcheck check --target-id <safe-id> --url <https-url> --mode <canary|steady> --surface <browser|api>")
}
