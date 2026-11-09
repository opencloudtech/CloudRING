// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Command cloudring-mutation measures the G2 diff mutation score defined in
// roadmap/EXECUTION_CONTRACT.md. It generates the mutants of gremlins v0.6.0
// (the default mutators plus INVERT_LOGICAL) in the files go build compiles,
// on the lines a candidate adds or changes against a base revision and on its
// untracked new files, runs `go test` on each mutant's package in a private
// copy of the module, and prints one row per mutant followed by the score.
// Every package with a mutant must pass `go test` unmutated in the copy before
// the mutants and in every copy after them, and a failing run counts as a kill
// only when it repeats (see confirmKill).
//
// Exit status: 0 when the score meets 4/5, 1 when it does not, 2 for invalid
// arguments or a failed measurement: a package that fails without a mutant, a
// diff the tool cannot read in full, or a compiled file it cannot mutate.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// defaultTimeout is the go test -timeout of one mutant run.
const defaultTimeout = 2 * time.Minute

const usage = "usage: cloudring-mutation --base REV --packages DIR[,DIR...] [--root DIR] [--timeout 2m] [--workers 4]"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("cloudring-mutation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", ".", "module root")
	base := flags.String("base", "", "base revision, normally the merge-base of the candidate")
	packages := flags.String("packages", "", "comma-separated package directories relative to the root")
	timeout := flags.Duration("timeout", defaultTimeout, "go test -timeout of each mutant run")
	workers := flags.Int("workers", 4, "mutants run in parallel, each in its own copy of the module")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *base == "" || strings.HasPrefix(*base, "-") ||
		*packages == "" || *timeout <= 0 || *workers < 1 {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	if info, err := os.Stat(filepath.Join(*root, "go.mod")); err != nil || !info.Mode().IsRegular() {
		_, _ = fmt.Fprintln(stderr, "cloudring-mutation: --root must be a module root containing go.mod")
		return 2
	}
	dirs, err := packageDirs(*root, *packages)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cloudring-mutation:", err)
		return 2
	}
	changes, err := candidateChanges(*root, *base, dirs)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cloudring-mutation:", err)
		return 2
	}
	sites, err := enumerate(*root, dirs, changes)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cloudring-mutation:", err)
		return 2
	}
	results, err := execute(ctx, *root, sites, *timeout, *workers)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cloudring-mutation:", err)
		return 2
	}
	met, err := report(stdout, *base, dirs, *timeout, *workers, results)
	if err != nil {
		return 2
	}
	if !met {
		return 1
	}
	return 0
}

// packageDirs validates the comma-separated package directories: each must be
// a relative directory inside the module root.
func packageDirs(root, list string) ([]string, error) {
	var dirs []string
	for _, item := range strings.Split(list, ",") {
		dir := path.Clean(filepath.ToSlash(strings.TrimSpace(item)))
		if dir == "." || dir == "" || path.IsAbs(dir) || dir == ".." || strings.HasPrefix(dir, "../") || strings.HasPrefix(dir, "-") {
			return nil, fmt.Errorf("package directory %q must be a directory inside the module root", item)
		}
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("package directory %q not found", item)
		}
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs, nil
}

// score holds G2 counts: killed over KILLED + LIVED + TIMED OUT + UNSTABLE.
type score struct {
	killed, total int
}

func (s score) meets() bool { return s.total > 0 && 5*s.killed >= 4*s.total }

func (s score) String() string {
	if s.total == 0 {
		return fmt.Sprintf("%d/%d", s.killed, s.total)
	}
	return fmt.Sprintf("%d/%d = %.4f", s.killed, s.total, float64(s.killed)/float64(s.total))
}

func tally(results []result, include func(result) bool) score {
	var s score
	for _, r := range results {
		if !include(r) {
			continue
		}
		switch r.Status {
		case statusKilled:
			s.killed++
			s.total++
		case statusLived, statusTimedOut, statusUnstable:
			s.total++
		}
	}
	return s
}

// report prints one tab-separated row per mutant and the score.
func report(w io.Writer, base string, dirs []string, timeout time.Duration, workers int, results []result) (bool, error) {
	out := bufio.NewWriter(w)
	_, _ = fmt.Fprintf(out, "# cloudring-mutation base=%s packages=%s timeout=%s workers=%d mutants=%d\n", base, strings.Join(dirs, ","), timeout, workers, len(results))
	if len(results) > 0 {
		sites := make([]site, len(results))
		for i, r := range results {
			sites[i] = r.site
		}
		_, _ = fmt.Fprintf(out, "# baseline: go test passed without mutants in the private copy before the mutants and in all %d copies after them: %s\n", workers, strings.Join(sitePackages(sites), ","))
	}
	_, _ = fmt.Fprintln(out, "STATUS\tLOCATION\tTYPE\tCHANGE\tFIRST FAILURE")
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Status]++
		_, _ = fmt.Fprintf(out, "%s\t%s\t%s\t%s -> %s\t%s\n", r.Status, r.location(), r.Type, r.From, r.To, r.Failure)
	}
	all := tally(results, func(result) bool { return true })
	defaults := tally(results, func(r result) bool { return r.Type != "INVERT_LOGICAL" })
	_, _ = fmt.Fprintf(out, "# statuses: KILLED=%d LIVED=%d TIMED OUT=%d UNSTABLE=%d NOT VIABLE=%d KILLED_BY_VET=%d\n"+
		"# default mutators only: %s\n"+
		"# G2 killedMutants=%d totalMutants=%d score=%s threshold=4/5 met=%t\n",
		counts[statusKilled], counts[statusLived], counts[statusTimedOut], counts[statusUnstable], counts[statusNotViable], counts[statusKilledByVet],
		defaults, all.killed, all.total, all, all.meets())
	return all.meets(), out.Flush()
}
