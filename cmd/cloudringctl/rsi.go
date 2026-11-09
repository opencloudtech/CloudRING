// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/opencloudtech/CloudRING/pkg/rsi"
)

// maxRSIProfileBytes matches the evaluator's own profile bound; one extra byte
// lets ParseProfile reject an oversized file instead of a silently cut one.
const maxRSIProfileBytes = 1 << 20

// runRSICommand runs `rsi evaluate --profile <file>`: it prints the RSI
// governance report as JSON and exits 0 only for a pass verdict, 1 for a
// fail verdict and 2 for invalid arguments or an unreadable profile.
func runRSICommand(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "evaluate" {
		_, _ = fmt.Fprintln(errOut, "cloudringctl rsi: expected evaluate --profile <file>")
		return 2
	}
	flags := flag.NewFlagSet("cloudringctl rsi evaluate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profilePath := flags.String("profile", "", "RSI candidate profile JSON file")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || strings.TrimSpace(*profilePath) == "" {
		_, _ = fmt.Fprintln(errOut, "cloudringctl rsi: expected evaluate --profile <file> without trailing arguments")
		return 2
	}
	file, err := os.Open(*profilePath) // #nosec G304 -- explicit local profile input, read-only and bounded below.
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "cloudringctl rsi: cannot open profile")
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxRSIProfileBytes+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_, _ = fmt.Fprintln(errOut, "cloudringctl rsi: cannot read profile")
		return 2
	}
	profile, err := rsi.ParseProfile(raw)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "cloudringctl rsi: %v\n", err)
		return 2
	}
	report, err := rsi.EvaluateCandidate(profile)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "cloudringctl rsi: %v\n", err)
		return 2
	}
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return 1
	}
	if report.Verdict != rsi.VerdictPass {
		return 1
	}
	return 0
}
