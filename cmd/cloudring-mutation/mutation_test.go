// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"context"
	"errors"
	"fmt"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const sample = `package p

func f(a, b int, c, d bool, s string) (int, bool, string) {
	x := a - b
	x++
	x += 2
	y := -x * a / b % 3
	return x, a < b && c || d, s + "!"
}
`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func siteKeys(sites []site) []string {
	var keys []string
	for _, s := range sites {
		keys = append(keys, fmt.Sprintf("%d:%d %s %s->%s", s.Line, s.Col, s.Type, s.From, s.To))
	}
	return keys
}

// Sites follow the gremlins v0.6.0 token table for the default mutators plus
// INVERT_LOGICAL: assignment operators, unary NOT and loop control are not
// mutated, a minus yields INVERT_NEGATIVES before ARITHMETIC_BASE, and only
// changed lines of files go build compiles count (not tests, testdata or
// files a build constraint excludes).
func TestEnumerateUsesTheGremlinsTokenTable(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.test/m\n\ngo 1.21\n")
	writeFile(t, filepath.Join(root, "p", "p.go"), sample)
	writeFile(t, filepath.Join(root, "p", "p_test.go"), "package p\n\nvar z = 1 + 2\n")
	writeFile(t, filepath.Join(root, "p", "ignored.go"), "//go:build ignore\n\npackage p\n\nvar z = 1 + 2\n")
	writeFile(t, filepath.Join(root, "p", "testdata", "x.go"), "package x\n\nvar z = 1 + 2\n")
	all := map[string]bool{"p/p.go": true, "p/p_test.go": true, "p/ignored.go": true, "p/testdata/x.go": true}
	got, err := enumerate(root, []string{"p"}, changeSet{newFiles: all})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"4:9 INVERT_NEGATIVES -->+", "4:9 ARITHMETIC_BASE -->+",
		"5:3 INCREMENT_DECREMENT ++->--",
		"7:7 INVERT_NEGATIVES -->+", "7:7 ARITHMETIC_BASE -->+",
		"7:10 ARITHMETIC_BASE *->/", "7:14 ARITHMETIC_BASE /->*", "7:18 ARITHMETIC_BASE %->*",
		"8:14 CONDITIONALS_BOUNDARY <-><=", "8:14 CONDITIONALS_NEGATION <->>=",
		"8:18 INVERT_LOGICAL &&->||", "8:23 INVERT_LOGICAL ||->&&",
		"8:31 ARITHMETIC_BASE +->-",
	}
	if keys := siteKeys(got); !reflect.DeepEqual(keys, want) {
		t.Fatalf("sites:\n%s\nwant:\n%s", strings.Join(keys, "\n"), strings.Join(want, "\n"))
	}
	for _, s := range got {
		if s.File != "p/p.go" {
			t.Fatalf("site outside the package file: %+v", s)
		}
	}
	got, err = enumerate(root, []string{"p"}, changeSet{lines: map[string]map[int]bool{"p/p.go": {5: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if keys := siteKeys(got); !reflect.DeepEqual(keys, []string{"5:3 INCREMENT_DECREMENT ++->--"}) {
		t.Fatalf("changed-line sites: %v", keys)
	}
}

// A mutant changes one AST node; printing keeps that node's meaning, so the
// outer operator of a chain becomes (c || d) && e, not c || d && e.
func TestApplyChangesOneNodeOfTheTree(t *testing.T) {
	src := []byte("package p\n\nfunc g(c, d, e bool) bool {\n\treturn c || d || e\n}\n")
	for col, want := range map[int]string{11: "return c && d || e", 16: "return (c || d) && e"} {
		out, err := apply(src, site{File: "p.go", Line: 4, Col: col, Type: "INVERT_LOGICAL", From: token.LOR, To: token.LAND})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), want) {
			t.Fatalf("column %d: %s", col, out)
		}
	}
	if _, err := apply(src, site{File: "p.go", Line: 4, Col: 13, Type: "INVERT_LOGICAL", From: token.LOR, To: token.LAND}); err == nil {
		t.Fatal("a position without the token was mutated")
	}
}

func TestParseUnifiedDiffKeepsOnlyNewSideLines(t *testing.T) {
	diff := strings.Join([]string{
		"diff --git a/p/a.go b/p/a.go",
		"index 1..2 100644",
		"--- a/p/a.go",
		"+++ b/p/a.go",
		"@@ -3,0 +4,2 @@ func f() {",
		"+++ x",
		"+\ty++",
		"@@ -10 +12 @@",
		"-\told",
		"+\tnew",
		`\ No newline at end of file`,
		"@@ -20,2 +21,0 @@",
		"-\tgone",
		"-\tgone",
		"diff --git a/p/b.go b/p/b.go",
		"deleted file mode 100644",
		"--- a/p/b.go",
		"+++ /dev/null",
		"@@ -1 +0,0 @@",
		"-package p",
		"diff --git a/p/sp ace.go b/p/sp ace.go",
		"new file mode 100644",
		"--- /dev/null",
		"+++ b/p/sp ace.go\t",
		"@@ -0,0 +1 @@",
		"+package p",
	}, "\n")
	got, err := parseUnifiedDiff([]byte(diff))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[int]bool{"p/a.go": {4: true, 5: true, 12: true}, "p/sp ace.go": {1: true}}
	if !reflect.DeepEqual(got.lines, want) || len(got.newFiles) != 0 {
		t.Fatalf("changed lines %v, new files %v", got.lines, got.newFiles)
	}
	head := "diff --git a/p/x.go b/p/x.go\n"
	for name, bad := range map[string]string{
		"unknown prefix":      head + "--- a/p/x.go\n+++ w/p/x.go\n",
		"quoted name":         head + "--- a/p/x.go\n+++ \"b/p/q\\\"uote.go\"\n",
		"binary notice":       head + "index 1..2 100644\nBinary files a/p/x.go and b/p/x.go differ\n",
		"rename header":       head + "similarity index 100%\nrename from p/x.go\nrename to p/y.go\n",
		"hunk before name":    head + "@@ -1 +1 @@\n-a\n+b\n",
		"short hunk":          head + "--- a/p/x.go\n+++ b/p/x.go\n@@ -1 +1,2 @@\n-a\n+b\n",
		"text after hunk":     head + "--- a/p/x.go\n+++ b/p/x.go\n@@ -1 +1 @@\n-a\n+b\n c\n",
		"text before a file":  "warning: something\n",
		"tab without a space": head + "--- a/p/x.go\n+++ b/p/x.go\t\n",
	} {
		if _, err := parseUnifiedDiff([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClassify(t *testing.T) {
	failed := errors.New("exit status 1")
	builds := func(ok bool) func() bool { return func() bool { return ok } }
	for _, tc := range []struct {
		name   string
		run    testRun
		builds bool
		want   string
	}{
		{"tests pass", testRun{}, true, statusLived},
		{"a test fails", testRun{err: failed, output: "--- FAIL: TestX (0.00s)\nFAIL\n"}, true, statusKilled},
		{"a test panics", testRun{err: failed, output: "panic: runtime error\nFAIL\tp\t0.01s\n"}, true, statusKilled},
		{"go test timeout", testRun{err: failed, output: "panic: test timed out after 2m0s\n"}, true, statusTimedOut},
		{"run outlived the allowance", testRun{err: failed, expired: true}, true, statusTimedOut},
		{"does not compile", testRun{err: failed, output: "FAIL\tp [build failed]\n"}, false, statusNotViable},
		{"go vet rejects", testRun{err: failed, output: "FAIL\tp [build failed]\n"}, true, statusKilledByVet},
		{"setup fails", testRun{err: failed, output: "FAIL\tp [setup failed]\n"}, false, statusNotViable},
	} {
		if got := classify(tc.run, builds(tc.builds)); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

// Real mutants of a small module, one per outcome, run through go test.
func TestExecuteClassifiesRealMutants(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go test on generated mutants")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.test/m\n\ngo 1.21\n")
	writeFile(t, filepath.Join(root, "p", "p.go"), `package p

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func Greeting(s string) string { return "hello " + s }

func Known(s string) bool { return s != "a" && s != "b" }

func Sum(n int) int {
	total := 0
	for i := 0; i < n; i++ {
		total += i
	}
	return total
}
`)
	writeFile(t, filepath.Join(root, "p", "p_test.go"), `package p

import "testing"

func TestP(t *testing.T) {
	if Max(1, 2) != 2 || Max(2, 1) != 2 || Greeting("x") != "hello x" || !Known("c") || Sum(3) != 3 {
		t.Fatal("unexpected result")
	}
}
`)
	sites, err := enumerate(root, []string{"p"}, changeSet{newFiles: map[string]bool{"p/p.go": true}})
	if err != nil {
		t.Fatal(err)
	}
	pick := map[string]site{}
	for _, s := range sites {
		switch {
		case s.Line == 4 && s.Type == "CONDITIONALS_BOUNDARY":
			pick[statusLived] = s // a >= b: Max(2, 2) is not tested
		case s.Line == 4 && s.Type == "CONDITIONALS_NEGATION":
			pick[statusKilled] = s
		case s.Line == 10 && s.Type == "ARITHMETIC_BASE":
			pick[statusNotViable] = s // string - string does not compile
		case s.Line == 12 && s.Type == "INVERT_LOGICAL":
			pick[statusKilledByVet] = s // s != "a" || s != "b": suspect or
		case s.Line == 16 && s.Type == "INCREMENT_DECREMENT":
			pick[statusTimedOut] = s // i-- never reaches n
		}
	}
	var chosen []site
	var want []string
	for _, status := range []string{statusLived, statusKilled, statusNotViable, statusKilledByVet, statusTimedOut} {
		s, ok := pick[status]
		if !ok {
			t.Fatalf("no site for %s in %v", status, siteKeys(sites))
		}
		chosen, want = append(chosen, s), append(want, status)
	}
	results, err := execute(context.Background(), root, chosen, 3*time.Second, len(chosen))
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range results {
		if r.Status != want[i] {
			t.Errorf("%s %s: %s, want %s", r.location(), r.Type, r.Status, want[i])
		}
	}
	if s := tally(results, func(result) bool { return true }); s != (score{killed: 1, total: 3}) || s.meets() {
		t.Fatalf("score %+v", s)
	}
	if got, err := os.ReadFile(filepath.Join(root, "p", "p.go")); err != nil || !strings.Contains(string(got), "if a > b {") {
		t.Fatalf("the measured tree was modified: %v", err)
	}
}

func TestRunRejectsInvalidArguments(t *testing.T) {
	root, bare := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.test/m\n")
	writeFile(t, filepath.Join(root, "p", "p.go"), "package p\n")
	writeFile(t, filepath.Join(bare, "p", "p.go"), "package p\n")
	for _, args := range [][]string{
		{},
		{"--packages", "p"},
		{"--base", "HEAD"},
		{"--base", "--upload-pack=x", "--packages", "p"},
		{"--root", bare, "--base", "HEAD", "--packages", "p"},
		{"--root", root, "--base", "HEAD", "--packages", "/p"},
		{"--root", root, "--base", "HEAD", "--packages", "../p"},
		{"--root", root, "--base", "HEAD", "--packages", "missing"},
		{"--root", root, "--base", "HEAD", "--packages", "p", "--timeout", "0s"},
		{"--root", root, "--base", "HEAD", "--packages", "p", "--workers", "0"},
		{"--root", root, "--base", "HEAD", "--packages", "p", "extra"},
	} {
		var out, errOut strings.Builder
		if code := run(context.Background(), args, &out, &errOut); code != 2 || out.Len() != 0 || errOut.Len() == 0 {
			t.Errorf("%v: exit=%d out=%q err=%q", args, code, out.String(), errOut.String())
		}
	}
}

func TestScoreThresholdIsInclusive(t *testing.T) {
	for _, tc := range []struct {
		s    score
		want bool
	}{{score{4, 5}, true}, {score{3, 4}, false}, {score{995, 1021}, true}, {score{0, 0}, false}} {
		if got := tc.s.meets(); got != tc.want {
			t.Errorf("%+v: %t", tc.s, got)
		}
	}
}

// Each worker mutates its own copy: version control metadata stays behind,
// links are recreated rather than followed, and file modes are kept.
func TestCopyModuleKeepsTheTreeWithoutVersionControl(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.test/m\n")
	writeFile(t, filepath.Join(root, "p", "run.sh"), "#!/bin/sh\n")
	if err := os.Chmod(filepath.Join(root, "p", "run.sh"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, ".git", "HEAD"), "ref: refs/heads/main\n")
	writeFile(t, filepath.Join(root, "sub", ".git"), "gitdir: elsewhere\n")
	if err := os.Symlink("../go.mod", filepath.Join(root, "p", "link")); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "copy")
	if err := copyModule(root, dst); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dst, "p", "run.sh")); err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("regular file: %v %v", info, err)
	}
	if link, err := os.Readlink(filepath.Join(dst, "p", "link")); err != nil || link != "../go.mod" {
		t.Fatalf("link: %q %v", link, err)
	}
	for _, name := range []string{".git", filepath.Join("sub", ".git")} {
		if _, err := os.Lstat(filepath.Join(dst, name)); !os.IsNotExist(err) {
			t.Fatalf("%s copied: %v", name, err)
		}
	}
	if err := copyModule(root, dst); err == nil {
		t.Fatal("copied into an existing directory")
	}
}

// gitIn runs git in repo with a fixed identity and no signing.
func gitIn(t *testing.T, repo string, args ...string) {
	t.Helper()
	if _, err := git(repo, append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"}, args...)...); err != nil {
		t.Fatal(err)
	}
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

// Changed lines come from the working tree against the base revision, with
// paths relative to a module root below the repository top level, and
// untracked files count as new.
func TestCandidateChangesReadsTheWorkingTreeAgainstBase(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	mod := filepath.Join(repo, "mod")
	writeFile(t, filepath.Join(mod, "go.mod"), "module example.test/m\n")
	writeFile(t, filepath.Join(mod, "p", "p.go"), "package p\n\nvar a = 1\n\nvar b = 2\n")
	writeFile(t, filepath.Join(mod, "q", "q.go"), "package q\n")
	gitIn(t, repo, "init", "-q")
	gitIn(t, repo, "add", ".")
	gitIn(t, repo, "commit", "-q", "-m", "base")
	writeFile(t, filepath.Join(mod, "p", "p.go"), "package p\n\nvar a = 1\n\nvar b = 3\nvar c = 4\n")
	writeFile(t, filepath.Join(mod, "p", "new.go"), "package p\n")
	writeFile(t, filepath.Join(mod, "q", "q.go"), "package q\n\nvar d = 5\n")
	got, err := candidateChanges(mod, "HEAD", []string{"p"})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]map[int]bool{"p/p.go": {5: true, 6: true}}; !reflect.DeepEqual(got.lines, want) {
		t.Fatalf("changed lines %v", got.lines)
	}
	if want := map[string]bool{"p/new.go": true}; !reflect.DeepEqual(got.newFiles, want) {
		t.Fatalf("new files %v", got.newFiles)
	}
}

const twice = "package p\n\nfunc Twice(a int) int { return a * 2 }\n"

// repoWithBase creates a module repository whose first commit holds files.
func repoWithBase(t *testing.T, files map[string]string) string {
	t.Helper()
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "go.mod"), "module example.test/m\n\ngo 1.21\n")
	for name, content := range files {
		writeFile(t, filepath.Join(repo, filepath.FromSlash(name)), content)
	}
	gitIn(t, repo, "init", "-q")
	gitIn(t, repo, "add", ".")
	gitIn(t, repo, "commit", "-q", "-m", "base")
	return repo
}

func runTool(t *testing.T, repo, base string) (int, string, string) {
	t.Helper()
	var out, errOut strings.Builder
	code := run(context.Background(), []string{"--root", repo, "--base", base, "--packages", "p", "--timeout", "30s", "--workers", "1"}, &out, &errOut)
	return code, out.String(), errOut.String()
}

// A file named with a space, a file marked -diff and a renamed file are
// candidate code like any other: their mutants are measured.
func TestRunMeasuresEveryChangedFile(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go test on generated mutants")
	}
	requireGit(t)
	test := "package p\n\nimport \"testing\"\n\nfunc TestTwice(t *testing.T) {\n\tif Twice(3) != 6 {\n\t\tt.Fatal(Twice(3))\n\t}\n}\n"
	for _, tc := range []struct {
		name, file string
		change     func(t *testing.T) (repo, base string)
	}{
		{"space in the name", "p/sp ace.go", func(t *testing.T) (string, string) {
			repo := repoWithBase(t, map[string]string{"p/p_test.go": test})
			writeFile(t, filepath.Join(repo, "p", "sp ace.go"), twice)
			gitIn(t, repo, "add", ".")
			gitIn(t, repo, "commit", "-q", "-m", "candidate")
			return repo, "HEAD~1"
		}},
		{"-diff attribute", "p/p.go", func(t *testing.T) (string, string) {
			repo := repoWithBase(t, map[string]string{".gitattributes": "*.go -diff\n", "p/p.go": "package p\n", "p/p_test.go": test})
			writeFile(t, filepath.Join(repo, "p", "p.go"), twice)
			return repo, "HEAD"
		}},
		{"renamed file", "p/new.go", func(t *testing.T) (string, string) {
			repo := repoWithBase(t, map[string]string{"p/old.go": twice, "p/p_test.go": test})
			gitIn(t, repo, "mv", "p/old.go", "p/new.go")
			return repo, "HEAD"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, base := tc.change(t)
			code, out, errOut := runTool(t, repo, base)
			row := "KILLED\t" + tc.file + ":3:34\tARITHMETIC_BASE\t* -> /\t"
			if code != 0 || !strings.Contains(out, "mutants=1\n") || !strings.Contains(out, row) {
				t.Fatalf("exit=%d\n%s%s", code, out, errOut)
			}
		})
	}
}

// A failure that does not depend on the mutant would count as a kill, so the
// tool stops when a package fails without a mutant: in the tree, only in the
// private copy (which has no .git), or only after its first run.
func TestRunStopsWhenAPackageFailsWithoutAMutant(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go test on generated mutants")
	}
	requireGit(t)
	for name, test := range map[string]string{
		"fails in the tree":      "if Twice(3) != 7 {\n\t\tt.Fatal(\"red\")\n\t}",
		"fails only in the copy": "if _, err := os.Stat(\"../.git\"); err != nil || Twice(3) != 6 {\n\t\tt.Fatal(err)\n\t}",
		"fails after its first run": "if _, err := os.Stat(\"ran\"); err == nil || Twice(3) != 6 {\n\t\tt.Fatal(\"second run\")\n\t}\n" +
			"\tif err := os.WriteFile(\"ran\", nil, 0o600); err != nil {\n\t\tt.Fatal(err)\n\t}",
	} {
		t.Run(name, func(t *testing.T) {
			repo := repoWithBase(t, nil)
			writeFile(t, filepath.Join(repo, "p", "p.go"), twice)
			writeFile(t, filepath.Join(repo, "p", "p_test.go"), "package p\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nvar _ = os.Stat\n\nfunc TestTwice(t *testing.T) {\n\t"+test+"\n}\n")
			if name != "fails in the tree" {
				if run := goTest(context.Background(), repo, "p", 30*time.Second); run.err != nil {
					t.Fatalf("the test must pass in the tree: %s", run.output)
				}
				_ = os.Remove(filepath.Join(repo, "p", "ran"))
			}
			code, out, errOut := runTool(t, repo, "HEAD")
			if code != 2 || out != "" || !strings.Contains(errOut, "fails without a mutant") {
				t.Fatalf("exit=%d\n%s%s", code, out, errOut)
			}
		})
	}
}

// runCounter is test code that counts its runs in a file of the package
// directory, the state a test must not keep but a measured package might.
const runCounter = `func runs(t *testing.T) int {
	b, _ := os.ReadFile("runs")
	n, _ := strconv.Atoi(string(b))
	n++
	if err := os.WriteFile("runs", []byte(strconv.Itoa(n)), 0o600); err != nil {
		t.Fatal(err)
	}
	return n
}
`

// A failure that does not repeat is not a kill. The mutant H(a)=a-1 is never
// checked; only a test that fails on alternating runs, or on runs a fixed
// pseudo-random sequence picks (seed 170: pass, fail, pass, pass, pass, pass),
// fails while it is applied. Both mutants must be UNSTABLE and not met.
func TestRunConfirmsKills(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go test on generated mutants")
	}
	requireGit(t)
	for name, check := range map[string]string{
		"alternating":         "if runs(t)%2 == 0 {\n\t\tt.Fatal(\"even run\")\n\t}",
		"seeded random flake": "if rand.New(rand.NewSource(170*1000 + int64(runs(t)))).Intn(2) == 0 {\n\t\tt.Fatal(\"flake\")\n\t}",
	} {
		t.Run(name, func(t *testing.T) {
			repo := repoWithBase(t, nil)
			writeFile(t, filepath.Join(repo, "p", "p.go"), "package p\n\nfunc H(a int) int { return a + 1 }\n")
			writeFile(t, filepath.Join(repo, "p", "p_test.go"), "package p\n\nimport (\n\t\"math/rand\"\n\t\"os\"\n\t\"strconv\"\n\t\"testing\"\n)\n\nvar _ = rand.New\n\n"+
				runCounter+"\nfunc TestH(t *testing.T) { _ = H(1) }\n\nfunc TestEnvironment(t *testing.T) {\n\t"+check+"\n}\n")
			code, out, errOut := runTool(t, repo, "HEAD")
			if code != 1 || !strings.Contains(out, "UNSTABLE\tp/p.go:3:30\tARITHMETIC_BASE\t+ -> -\t--- FAIL: TestEnvironment") ||
				!strings.Contains(out, "UNSTABLE=1 ") || !strings.Contains(out, "killedMutants=0 totalMutants=1 ") {
				t.Fatalf("exit=%d\n%s%s", code, out, errOut)
			}
		})
	}
}

// Code go build compiles is measured even when a //line directive renumbers
// it, and a compiled file the tool cannot mutate in place (a symbolic link)
// stops the run.
func TestRunMeasuresTheCodeGoBuildCompiles(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go test on generated mutants")
	}
	requireGit(t)
	base := map[string]string{"p/base.go": "package p\n", "p/p_test.go": "package p\n\nimport \"testing\"\n\nfunc TestP(t *testing.T) {}\n"}
	untested := "package p\n\nfunc Untested(a int) int { return a * 2 }\n"
	t.Run("line directive", func(t *testing.T) {
		repo := repoWithBase(t, base)
		writeFile(t, filepath.Join(repo, "p", "lined.go"), "package p\n\n//line lined.go:1000\nfunc Untested(a int) int { return a * 2 }\n")
		gitIn(t, repo, "add", ".")
		gitIn(t, repo, "commit", "-q", "-m", "candidate")
		code, out, errOut := runTool(t, repo, "HEAD~1")
		if code != 1 || !strings.Contains(out, "LIVED\tp/lined.go:4:37\tARITHMETIC_BASE\t* -> /\t") {
			t.Fatalf("exit=%d\n%s%s", code, out, errOut)
		}
	})
	t.Run("symbolic link", func(t *testing.T) {
		repo := repoWithBase(t, base)
		writeFile(t, filepath.Join(repo, "p", "_impl", "h.go"), untested)
		if err := os.Symlink(filepath.Join("_impl", "h.go"), filepath.Join(repo, "p", "hidden.go")); err != nil {
			t.Fatal(err)
		}
		gitIn(t, repo, "add", ".")
		gitIn(t, repo, "commit", "-q", "-m", "candidate")
		code, out, errOut := runTool(t, repo, "HEAD~1")
		if code != 2 || out != "" || !strings.Contains(errOut, "hidden.go") || !strings.Contains(errOut, "not a regular file") {
			t.Fatalf("exit=%d\n%s%s", code, out, errOut)
		}
	})
}
