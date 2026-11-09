// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var hunkHeader = regexp.MustCompile(`^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// fileHeaders are the extended header lines git prints for a file when
// renames, copies and binary output are off.
var fileHeaders = []string{"index ", "old mode ", "new mode ", "new file mode ", "deleted file mode ", "--- "}

// candidateChanges returns the lines of the working tree under dirs that the
// candidate adds or changes against base, and its untracked new files, with
// paths relative to root (which may be below the repository top level). A
// renamed file counts as new, and every file is compared as text, so neither
// rename detection nor diff attributes can hide a changed line.
func candidateChanges(root, base string, dirs []string) (changeSet, error) {
	diff, err := git(root, append([]string{"-c", "core.quotePath=false", "diff", "--no-renames", "--text", "--no-textconv",
		"--no-ext-diff", "--submodule=short", "-U0", "--no-color", "--relative", "--src-prefix=a/", "--dst-prefix=b/", base, "--"}, dirs...)...)
	if err != nil {
		return changeSet{}, err
	}
	changes, err := parseUnifiedDiff(diff)
	if err != nil {
		return changeSet{}, err
	}
	untracked, err := git(root, append([]string{"ls-files", "-z", "--others", "--exclude-standard", "--"}, dirs...)...)
	if err != nil {
		return changeSet{}, err
	}
	for _, name := range strings.Split(string(untracked), "\x00") {
		if name != "" {
			changes.newFiles[name] = true
		}
	}
	return changes, nil
}

// parseUnifiedDiff reads the output of candidateChanges' git diff: every line
// of a hunk's new side is a changed line. Any line it does not recognise,
// including a binary notice, a rename header or a quoted file name, is an
// error, so the measurement stops instead of skipping a file.
func parseUnifiedDiff(diff []byte) (changeSet, error) {
	changes := changeSet{newFiles: map[string]bool{}, lines: map[string]map[int]bool{}}
	const (
		outside = iota
		header
		hunk
	)
	state, current, named := outside, "", false
	oldLeft, newLeft := 0, 0
	scanner := bufio.NewScanner(bytes.NewReader(diff))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if state == hunk && (oldLeft > 0 || newLeft > 0 || strings.HasPrefix(line, `\`)) {
			switch {
			case strings.HasPrefix(line, "-") && oldLeft > 0:
				oldLeft--
			case strings.HasPrefix(line, "+") && newLeft > 0:
				newLeft--
			case !strings.HasPrefix(line, `\`):
				return changeSet{}, fmt.Errorf("unexpected line in hunk %q", line)
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "diff --git "):
			state, current, named = header, "", false
		case state != outside && strings.HasPrefix(line, "@@ "):
			m := hunkHeader.FindStringSubmatch(line)
			if m == nil || !named {
				return changeSet{}, fmt.Errorf("unsupported hunk header %q", line)
			}
			var start int
			var err error
			if oldLeft, err = hunkCount(m[1]); err != nil {
				return changeSet{}, err
			}
			if start, err = strconv.Atoi(m[2]); err != nil {
				return changeSet{}, err
			}
			if newLeft, err = hunkCount(m[3]); err != nil {
				return changeSet{}, err
			}
			if current != "" && newLeft > 0 {
				if changes.lines[current] == nil {
					changes.lines[current] = map[int]bool{}
				}
				for n := start; n < start+newLeft; n++ {
					changes.lines[current][n] = true
				}
			}
			state = hunk
		case state == header && strings.HasPrefix(line, "+++ "):
			name, err := newSideName(strings.TrimPrefix(line, "+++ "))
			if err != nil {
				return changeSet{}, err
			}
			current, named = name, true
		case state == header && hasPrefix(line, fileHeaders):
		case strings.HasPrefix(line, "Binary files "):
			return changeSet{}, fmt.Errorf("binary diff hides changed lines: %q", line)
		default:
			return changeSet{}, fmt.Errorf("unsupported diff line %q", line)
		}
	}
	if oldLeft > 0 || newLeft > 0 {
		return changeSet{}, fmt.Errorf("diff ends inside a hunk")
	}
	return changes, scanner.Err()
}

// newSideName returns the path of a "+++ " header, "" for a deleted file. Git
// appends a TAB to a name that contains a space and quotes names with other
// special characters; a quoted name is refused.
func newSideName(name string) (string, error) {
	if name == "/dev/null" {
		return "", nil
	}
	if trimmed := strings.TrimSuffix(name, "\t"); trimmed != name && strings.Contains(trimmed, " ") {
		name = trimmed
	}
	if !strings.HasPrefix(name, "b/") || strings.ContainsAny(name, "\t\"\\") {
		return "", fmt.Errorf("unsupported diff file name %q", name)
	}
	return strings.TrimPrefix(name, "b/"), nil
}

func hunkCount(s string) (int, error) {
	if s == "" {
		return 1, nil
	}
	return strconv.Atoi(s)
}

func hasPrefix(line string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func git(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...) // #nosec G204 -- fixed git binary; the base revision is checked not to be an option.
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
