// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/opencloudtech/CloudRING/internal/platformmanifest"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	os.Exit(run(*root, os.Stdout, os.Stderr))
}

func run(root string, stdout, stderr io.Writer) int {
	reports := make([]platformmanifest.Report, 0, 7)
	for _, verify := range []func(string) (platformmanifest.Report, error){
		platformmanifest.VerifySecretManager,
		platformmanifest.VerifyCertManager,
		platformmanifest.VerifyCSISnapshotAPI,
		platformmanifest.VerifyRookCephRBD,
		platformmanifest.VerifyLonghornThreeNode,
		platformmanifest.VerifyPostgreSQLHA,
		platformmanifest.VerifyCDI,
	} {
		report, err := verify(root)
		if err != nil {
			fmt.Fprintln(stderr, "platform manifest verification blocked")
			return 1
		}
		reports = append(reports, report)
	}
	liveStatus := "not-evaluated"
	for _, report := range reports {
		if report.LiveStatus == "blocked" {
			liveStatus = "blocked"
			break
		}
	}
	output := struct {
		Status     string                    `json:"status"`
		LiveStatus string                    `json:"liveStatus"`
		Profiles   []platformmanifest.Report `json:"profiles"`
	}{
		Status:     "source-contracts-verified",
		LiveStatus: liveStatus,
		Profiles:   reports,
	}
	if err := json.NewEncoder(stdout).Encode(output); err != nil {
		fmt.Fprintln(stderr, "encode platform manifest report")
		return 2
	}
	return 0
}
