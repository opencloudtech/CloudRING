// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Mutant statuses. KILLED, LIVED, TIMED OUT and UNSTABLE count in G2; a mutant
// that does not build (NOT VIABLE) or that go vet rejects during go test
// (KILLED_BY_VET) is not viable and is not counted. UNSTABLE is a failure that
// did not repeat under kill confirmation; it counts as not killed.
const (
	statusKilled      = "KILLED"
	statusLived       = "LIVED"
	statusTimedOut    = "TIMED OUT"
	statusUnstable    = "UNSTABLE"
	statusNotViable   = "NOT VIABLE"
	statusKilledByVet = "KILLED_BY_VET"
)

// buildAllowance is the time a mutant run may take beyond the go test
// -timeout for compiling and linking before it is stopped as TIMED OUT.
const buildAllowance = 5 * time.Minute

type result struct {
	site
	Status  string
	Failure string // first "--- FAIL" line, if any
}

// testRun is the outcome of one go test invocation.
type testRun struct {
	err    error
	output string
	// expired is set when the run outlived the -timeout plus buildAllowance.
	expired bool
}

// classify maps a go test run of a mutant to its status. builds reports
// whether the mutant compiles with vet off; it is consulted only for a run
// that go test reports as a build or setup failure.
func classify(run testRun, builds func() bool) string {
	switch {
	case run.expired || strings.Contains(run.output, "panic: test timed out after"):
		return statusTimedOut
	case run.err == nil:
		return statusLived
	case strings.Contains(run.output, "[build failed]") || strings.Contains(run.output, "[setup failed]"):
		if builds() {
			return statusKilledByVet
		}
		return statusNotViable
	default:
		return statusKilled
	}
}

func firstFailure(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "--- FAIL:") {
			return trimmed
		}
	}
	return ""
}

// failedTest returns the name in the first "--- FAIL: name (duration)" line.
func failedTest(output string) string {
	if fields := strings.Fields(firstFailure(output)); len(fields) > 2 {
		return fields[2]
	}
	return ""
}

// goTest runs go test in dir for the package directory pkg, in its own process
// group so that a test that signals its group cannot stop the measurement.
func goTest(ctx context.Context, dir, pkg string, timeout time.Duration, extra ...string) testRun {
	ctx, cancel := context.WithTimeout(ctx, timeout+buildAllowance)
	defer cancel()
	args := append([]string{"test", "-count=1", "-timeout", timeout.String()}, extra...)
	args = append(args, "./"+pkg+"/")
	cmd := exec.CommandContext(ctx, "go", args...) // #nosec G204 -- fixed go binary; the package path is validated relative to the module root.
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	ownProcessGroup(cmd)
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	return testRun{err: err, output: out.String(), expired: errors.Is(ctx.Err(), context.DeadlineExceeded)}
}

// execute runs every mutant once, each worker in its own copy of the module.
// Every package with a mutant must pass go test unmutated in a fresh copy
// before the mutants run and in every copy after them; otherwise a failure
// that does not depend on the mutant would count as a kill.
func execute(ctx context.Context, root string, sites []site, timeout time.Duration, workers int) ([]result, error) {
	if len(sites) == 0 {
		return nil, nil
	}
	scratch, err := os.MkdirTemp("", "cloudring-mutation-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	copies := make([]string, workers)
	for i := range copies {
		copies[i] = filepath.Join(scratch, fmt.Sprintf("module-%d", i))
		if err := copyModule(root, copies[i]); err != nil {
			return nil, err
		}
	}
	pkgs := sitePackages(sites)
	if err := baseline(ctx, copies[:1], pkgs, timeout); err != nil {
		return nil, fmt.Errorf("baseline before the mutants: %w", err)
	}
	results := make([]result, len(sites))
	jobs := make(chan int)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for _, copyDir := range copies {
		wg.Add(1)
		go func(copyDir string) {
			defer wg.Done()
			for i := range jobs {
				r, err := runMutant(ctx, copyDir, sites[i], timeout)
				if err != nil {
					errs <- err
					return
				}
				results[i] = r
			}
		}(copyDir)
	}
	var runErr error
feed:
	for i := range sites {
		select {
		case jobs <- i:
		case runErr = <-errs:
			break feed
		case <-ctx.Done():
			runErr = ctx.Err()
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if runErr == nil {
		select {
		case runErr = <-errs:
		default:
		}
	}
	if runErr != nil {
		return nil, runErr
	}
	if err := baseline(ctx, copies, pkgs, timeout); err != nil {
		return nil, fmt.Errorf("baseline after the mutants: %w", err)
	}
	return results, nil
}

// sitePackages returns the package directories that have mutants, sorted.
func sitePackages(sites []site) []string {
	seen := map[string]bool{}
	var pkgs []string
	for _, s := range sites {
		if pkg := path.Dir(s.File); !seen[pkg] {
			seen[pkg] = true
			pkgs = append(pkgs, pkg)
		}
	}
	sort.Strings(pkgs)
	return pkgs
}

// baseline requires every package to pass go test unmutated in each copy.
func baseline(ctx context.Context, copies, pkgs []string, timeout time.Duration) error {
	errs := make([]error, len(copies))
	var wg sync.WaitGroup
	for i, copyDir := range copies {
		wg.Add(1)
		go func(i int, copyDir string) {
			defer wg.Done()
			for _, pkg := range pkgs {
				if run := goTest(ctx, copyDir, pkg, timeout); run.err != nil {
					errs[i] = fmt.Errorf("go test ./%s/ fails without a mutant in copy %d: %s", pkg, i, failureSummary(run))
					return
				}
			}
		}(i, copyDir)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.Join(errs...)
}

// failureSummary names why a go test run failed in one line.
func failureSummary(run testRun) string {
	if classify(run, func() bool { return true }) == statusTimedOut {
		return "timed out"
	}
	if failure := firstFailure(run.output); failure != "" {
		return failure
	}
	for _, line := range strings.Split(run.output, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "# ") {
			return line
		}
	}
	return run.err.Error()
}

func runMutant(ctx context.Context, copyDir string, s site, timeout time.Duration) (result, error) {
	module, err := os.OpenRoot(copyDir)
	if err != nil {
		return result{}, err
	}
	defer func() { _ = module.Close() }()
	name := filepath.FromSlash(s.File)
	info, err := module.Stat(name)
	if err != nil {
		return result{}, err
	}
	original, err := module.ReadFile(name)
	if err != nil {
		return result{}, err
	}
	mutated, err := apply(original, s)
	if err != nil {
		return result{}, err
	}
	perm := info.Mode().Perm()
	if err := module.WriteFile(name, mutated, perm); err != nil {
		return result{}, err
	}
	pkg := path.Dir(s.File)
	run := goTest(ctx, copyDir, pkg, timeout)
	status := classify(run, func() bool {
		return goTest(ctx, copyDir, pkg, timeout, "-vet=off", "-run", "^$").err == nil
	})
	if status == statusKilled {
		if status, err = confirmKill(ctx, module, copyDir, pkg, name, original, mutated, perm, timeout, failedTest(run.output)); err != nil {
			return result{}, err
		}
	}
	if err := module.WriteFile(name, original, perm); err != nil {
		return result{}, fmt.Errorf("restore %s: %w", s.File, err)
	}
	if ctx.Err() != nil {
		return result{}, ctx.Err()
	}
	return result{site: s, Status: status, Failure: firstFailure(run.output)}, nil
}

// confirmKill reruns the package of a mutant whose first run failed in test:
// unmutated it must pass twice in a row, and the mutant must then fail again
// with the same first failing test. Otherwise the failure did not depend on
// the mutant alone and the mutant is UNSTABLE. Two consecutive unmutated runs
// break a failure that alternates between runs.
func confirmKill(ctx context.Context, module *os.Root, copyDir, pkg, name string, original, mutated []byte, perm fs.FileMode, timeout time.Duration, test string) (string, error) {
	if err := module.WriteFile(name, original, perm); err != nil {
		return "", err
	}
	for range 2 {
		if goTest(ctx, copyDir, pkg, timeout).err != nil {
			return statusUnstable, nil
		}
	}
	if err := module.WriteFile(name, mutated, perm); err != nil {
		return "", err
	}
	again := goTest(ctx, copyDir, pkg, timeout)
	if classify(again, func() bool { return true }) != statusKilled || failedTest(again.output) != test {
		return statusUnstable, nil
	}
	return statusKilled, nil
}

// copyModule copies the module tree at root to the new directory dst without
// version control metadata. Symbolic links are recreated, not followed, and
// every access stays inside the two trees.
func copyModule(root, dst string) error {
	src, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	out, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	return fs.WalkDir(src.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Name() == ".git" && name != "." {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		switch mode := entry.Type(); {
		case entry.IsDir():
			return out.MkdirAll(name, 0o700)
		case mode&fs.ModeSymlink != 0:
			link, err := src.Readlink(name)
			if err != nil {
				return err
			}
			return out.Symlink(link, name)
		case mode.IsRegular():
			return copyFile(src, out, name)
		}
		return nil
	})
}

func copyFile(src, dst *os.Root, name string) error {
	in, err := src.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := dst.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
