// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/sourcecheck"
)

var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var remoteNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	var options sourcecheck.Options
	var err error
	if len(args) != 0 && args[0] == "pre-push-hook" {
		options, err = parsePrePushHook(args, stdin)
	} else {
		options, err = parseArgs(args)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	report, err := sourcecheck.Scan(options)
	if err != nil {
		fmt.Fprintf(stderr, "source-safety scan failed: %v\n", err)
		return 2
	}
	if options.ReportPath != "" {
		if err := writeDetailedReport(options.ReportPath, report); err != nil {
			fmt.Fprintln(stderr, "write source-safety report failed")
			return 2
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	output := any(report)
	if options.OutputFormat != "json" {
		output = struct {
			Status        string            `json:"status"`
			Scope         sourcecheck.Scope `json:"scope"`
			ScannedFiles  int               `json:"scannedFiles"`
			ScannedInputs int               `json:"scannedInputs"`
			Findings      int               `json:"findings"`
		}{report.Status, report.Scope, len(report.ScannedFiles), len(report.ScannedInputs), len(report.Findings)}
	}
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintln(stderr, "encode source-safety output failed")
		return 2
	}
	if !report.Passed {
		fmt.Fprintf(stderr, "source-safety blocked: %d finding(s)\n", len(report.Findings))
		return 1
	}
	return 0
}

func parseArgs(args []string) (sourcecheck.Options, error) {
	if len(args) == 0 || args[0] != "scan" {
		return sourcecheck.Options{}, usageError()
	}
	flags := flag.NewFlagSet("cloudring-sourcecheck scan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "repository root (defaults to the current Git repository)")
	scope := flags.String("scope", string(sourcecheck.ScopeFull), "scan scope: full, tracked, changed, pre-push, or files")
	base := flags.String("base", "", "exclusive base commit for pre-push scope")
	head := flags.String("head", "", "inclusive head commit for pre-push scope (defaults to HEAD)")
	remoteName := flags.String("remote-name", "", "validated target remote name for zero-base discovery")
	remoteURLSHA256 := flags.String("remote-url-sha256", "", "SHA-256 identity of the actual Git-provided push URL")
	format := flags.String("format", "summary", "output format: summary or json")
	reportPath := flags.String("report", "", "new file for a detailed JSON report")
	recurseGitlinks := flags.Bool("recurse-gitlinks", false, "recursively scan clean initialized gitlinks")
	var files stringList
	var remoteRefs stringList
	var allowances allowanceList
	flags.Var(&files, "file", "repository-relative file for files scope; repeatable")
	flags.Var(&remoteRefs, "remote-ref", "exact target-remote ref excluded for a zero-base pre-push scan; repeatable")
	flags.Var(&allowances, "allow-non-text", "reviewed non-text canonical-path=sha256 allowance; repeatable")
	if err := flags.Parse(args[1:]); err != nil {
		return sourcecheck.Options{}, errors.New("invalid sourcecheck option")
	}
	if flags.NArg() != 0 {
		return sourcecheck.Options{}, errors.New("unexpected positional sourcecheck arguments")
	}
	parsedScope := sourcecheck.Scope(strings.TrimSpace(*scope))
	switch parsedScope {
	case sourcecheck.ScopeFull, sourcecheck.ScopeTracked, sourcecheck.ScopeChanged, sourcecheck.ScopePrePush, sourcecheck.ScopeFiles:
	default:
		return sourcecheck.Options{}, errors.New("unsupported --scope value")
	}
	if (len(remoteRefs) != 0 || *remoteName != "" || *remoteURLSHA256 != "") && parsedScope != sourcecheck.ScopePrePush {
		return sourcecheck.Options{}, errors.New("target-remote options are valid only for pre-push scope")
	}
	if *remoteName != "" || *remoteURLSHA256 != "" || len(remoteRefs) != 0 {
		if !remoteNamePattern.MatchString(*remoteName) || !sha256Pattern.MatchString(*remoteURLSHA256) {
			return sourcecheck.Options{}, errors.New("target-remote options require a safe name and URL SHA-256 identity")
		}
	}
	if *format != "summary" && *format != "json" {
		return sourcecheck.Options{}, errors.New("unsupported --format value")
	}
	if strings.IndexByte(*reportPath, 0) >= 0 {
		return sourcecheck.Options{}, errors.New("invalid --report path")
	}
	return sourcecheck.Options{
		Root:              *root,
		Scope:             parsedScope,
		Files:             append([]string{}, files...),
		Base:              *base,
		Head:              *head,
		RemoteName:        *remoteName,
		RemoteURLSHA256:   strings.ToLower(*remoteURLSHA256),
		RemoteRefs:        append([]string{}, remoteRefs...),
		NonTextAllowances: append([]sourcecheck.NonTextAllowance{}, allowances.values...),
		RecurseGitlinks:   *recurseGitlinks,
		OutputFormat:      *format,
		ReportPath:        *reportPath,
	}, nil
}

func parsePrePushHook(args []string, stdin io.Reader) (sourcecheck.Options, error) {
	positionals := args[1:]
	if len(positionals) != 1 || !remoteNamePattern.MatchString(positionals[0]) {
		return sourcecheck.Options{}, errors.New("pre-push hook requires one safe Git remote name")
	}
	// Git supplies the remote URL to the shell hook. The tracked hook writes it as
	// a NUL-delimited stdin prefix, never argv/environment/file/output. Retain only
	// its SHA-256 identity so sourcecheck can prove which configured target it saw.
	reader := bufio.NewReaderSize(stdin, 1024*1024)
	remoteURL, readErr := reader.ReadSlice(0)
	if readErr != nil || len(remoteURL) <= 1 {
		return sourcecheck.Options{}, errors.New("pre-push hook could not identify the actual push target")
	}
	remoteURL = remoteURL[:len(remoteURL)-1]
	remoteURLDigest := sha256.Sum256(remoteURL)
	for index := range remoteURL {
		remoteURL[index] = 0
	}
	updates := make([]sourcecheck.PushUpdate, 0)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 || !validRef(fields[0], true) || !validOID(fields[1]) || !validRef(fields[2], false) || !validOID(fields[3]) {
			return sourcecheck.Options{}, errors.New("pre-push hook received an invalid ref update")
		}
		updates = append(updates, sourcecheck.PushUpdate{
			LocalRef: fields[0], LocalOID: strings.ToLower(fields[1]), RemoteRef: fields[2], RemoteOID: strings.ToLower(fields[3]),
		})
	}
	if err := scanner.Err(); err != nil {
		return sourcecheck.Options{}, errors.New("pre-push hook could not read all ref updates")
	}
	return sourcecheck.Options{
		Scope: sourcecheck.ScopePrePush, RemoteName: positionals[0], RemoteURLSHA256: hex.EncodeToString(remoteURLDigest[:]),
		PushUpdates: updates, OutputFormat: "summary",
	}, nil
}

func writeDetailedReport(path string, report sourcecheck.Report) error {
	// #nosec G304 -- this explicit operator path is opened O_EXCL with mode 0600;
	// existing files and final-component symlinks cannot be followed or replaced.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create detailed report failed")
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encodeErr := encoder.Encode(report)
	closeErr := file.Close()
	if encodeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.New("persist detailed report failed")
	}
	return nil
}

func validRef(value string, local bool) bool {
	if local {
		// Git passes the symbolic source name verbatim when a caller uses the
		// common `git push <remote> HEAD:<remote-ref>` form. The scanner relies on
		// the separately validated object ID, never on this display name.
		if value == "(delete)" || value == "HEAD" {
			return true
		}
	}
	return strings.HasPrefix(value, "refs/") && !strings.HasPrefix(value, "-") && !strings.ContainsAny(value, "\x00\r\n\t ")
}

func validOID(value string) bool {
	return (len(value) == 40 || len(value) == 64) && isHex(value)
}

func isHex(value string) bool {
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
			return false
		}
	}
	return value != ""
}

type stringList []string

func (values *stringList) String() string {
	return "<repeatable-value>"
}

func (values *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || strings.IndexByte(value, 0) >= 0 {
		return errors.New("repeatable option requires a non-empty value")
	}
	*values = append(*values, value)
	return nil
}

type allowanceList struct {
	values []sourcecheck.NonTextAllowance
	seen   map[string]bool
}

func (allowances *allowanceList) String() string {
	return "<reviewed-canonical-path=sha256>"
}

func (allowances *allowanceList) Set(value string) error {
	path, digest, ok := strings.Cut(value, "=")
	path = strings.TrimSpace(path)
	digest = strings.TrimSpace(digest)
	canonical, canonicalErr := canonicalAllowancePath(path)
	if !ok || canonicalErr != nil || !sha256Pattern.MatchString(digest) {
		return errors.New("--allow-non-text requires canonical-path=64-hex-sha256")
	}
	if allowances.seen == nil {
		allowances.seen = map[string]bool{}
	}
	normalizedDigest := strings.ToLower(digest)
	allowanceIdentity := canonical + "\x00" + normalizedDigest
	if allowances.seen[allowanceIdentity] {
		return errors.New("duplicate canonical --allow-non-text path and digest rejected")
	}
	allowances.seen[allowanceIdentity] = true
	allowances.values = append(allowances.values, sourcecheck.NonTextAllowance{Path: canonical, SHA256: normalizedDigest})
	return nil
}

func canonicalAllowancePath(raw string) (string, error) {
	if raw == "" || strings.IndexByte(raw, 0) >= 0 {
		return "", errors.New("invalid allowance path")
	}
	normalized := strings.ReplaceAll(raw, `\`, "/")
	if strings.HasPrefix(normalized, "/") || strings.HasPrefix(normalized, "//") || (len(normalized) >= 2 && normalized[1] == ':' && ((normalized[0] >= 'A' && normalized[0] <= 'Z') || (normalized[0] >= 'a' && normalized[0] <= 'z'))) {
		return "", errors.New("allowance path must be repository-relative")
	}
	parts := strings.Split(normalized, "/")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			return "", errors.New("allowance path escapes repository")
		default:
			clean = append(clean, part)
		}
	}
	if len(clean) == 0 {
		return "", errors.New("allowance path is empty")
	}
	return strings.Join(clean, "/"), nil
}

func usageError() error {
	return errors.New("usage: cloudring-sourcecheck scan [--scope full|tracked|changed|pre-push|files] [--root path] [--base sha --head sha] [--remote-name safe-name --remote-url-sha256 digest --remote-ref exact-ref] [--file path] [--allow-non-text canonical-path=sha256] [--recurse-gitlinks] [--format summary|json] [--report new-path]")
}
