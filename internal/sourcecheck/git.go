// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package sourcecheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type indexEntry struct {
	mode  string
	oid   string
	stage int
	path  string
}

type treeEntry struct {
	mode       string
	objectType string
	oid        string
	path       string
}

type publishedObject struct {
	objectType string
	data       []byte
}

const maxGitMetadataBytes = 32 * 1024 * 1024
const maxCapturedInputBytes = 64 * 1024 * 1024
const maxSourceInputs = 100_000
const maxHistoryCommits = 10_000
const maxAnnotatedTagDepth = 64
const maxAnnotatedTagHeaderLineBytes = 4 * 1024
const maxAggregateMetadataBytes = 128 * 1024 * 1024
const maxSourceFindings = 10_000
const maxReadinessClauses = 100_000
const maxSourceLines = 500_000

type resourceLimits struct {
	capturedBytes int64
	inputCount    int
	commitCount   int
	metadataBytes int64
	findingCount  int
	clauseCount   int
	lineCount     int
}

type scanBudget struct {
	limits        resourceLimits
	capturedBytes int64
	inputCount    int
	commitCount   int
	metadataBytes int64
}

func newScanBudget(requested *resourceLimits) *scanBudget {
	limits := resourceLimits{
		capturedBytes: maxCapturedInputBytes,
		inputCount:    maxSourceInputs,
		commitCount:   maxHistoryCommits,
		metadataBytes: maxAggregateMetadataBytes,
		findingCount:  maxSourceFindings,
		clauseCount:   maxReadinessClauses,
		lineCount:     maxSourceLines,
	}
	if requested != nil {
		if requested.capturedBytes > 0 && requested.capturedBytes < limits.capturedBytes {
			limits.capturedBytes = requested.capturedBytes
		}
		if requested.inputCount > 0 && requested.inputCount < limits.inputCount {
			limits.inputCount = requested.inputCount
		}
		if requested.commitCount > 0 && requested.commitCount < limits.commitCount {
			limits.commitCount = requested.commitCount
		}
		if requested.metadataBytes > 0 && requested.metadataBytes < limits.metadataBytes {
			limits.metadataBytes = requested.metadataBytes
		}
		if requested.findingCount > 0 && requested.findingCount < limits.findingCount {
			limits.findingCount = requested.findingCount
		}
		if requested.clauseCount > 0 && requested.clauseCount < limits.clauseCount {
			limits.clauseCount = requested.clauseCount
		}
		if requested.lineCount > 0 && requested.lineCount < limits.lineCount {
			limits.lineCount = requested.lineCount
		}
	}
	return &scanBudget{limits: limits}
}

func (budget *scanBudget) consumeInput(input scanInput) error {
	size := int64(len(input.path) + len(input.variant) + len(input.data))
	if budget.inputCount >= budget.limits.inputCount || size > budget.limits.capturedBytes-budget.capturedBytes {
		return errors.New("aggregate source input exceeds the source-safety budget")
	}
	budget.inputCount++
	budget.capturedBytes += size
	return nil
}

func (budget *scanBudget) consumeCommit() error {
	if budget.commitCount >= budget.limits.commitCount {
		return errors.New("pre-push history exceeds the source-safety commit budget")
	}
	budget.commitCount++
	return nil
}

func (budget *scanBudget) consumeMetadata(size int) error {
	value := int64(size)
	if value > budget.limits.metadataBytes-budget.metadataBytes {
		return errors.New("aggregate Git metadata exceeds the source-safety budget")
	}
	budget.metadataBytes += value
	return nil
}

func (budget *scanBudget) consumeExpansion(size int64) error {
	if size <= 0 {
		return nil
	}
	if size > budget.limits.capturedBytes-budget.capturedBytes {
		return errors.New("decoded source input exceeds the source-safety budget")
	}
	budget.capturedBytes += size
	return nil
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

type inputCollector struct {
	inputs []scanInput
	budget *scanBudget
}

func (collector *inputCollector) add(inputs ...scanInput) error {
	for _, input := range inputs {
		if err := collector.budget.consumeInput(input); err != nil {
			return err
		}
		collector.inputs = append(collector.inputs, input)
	}
	return nil
}

func (output *cappedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := output.limit - output.buffer.Len()
	if remaining <= 0 {
		output.exceeded = true
		return original, nil
	}
	if len(value) > remaining {
		output.exceeded = true
		value = value[:remaining]
	}
	_, _ = output.buffer.Write(value)
	return original, nil
}

func collectInputs(options Options) (string, []scanInput, error) {
	return collectInputsVisited(options, map[string]bool{}, newScanBudget(options.limits))
}

func collectInputsVisited(options Options, visited map[string]bool, budget *scanBudget) (string, []scanInput, error) {
	root, err := resolveRepositoryRoot(options.Root)
	if err != nil {
		return "", nil, err
	}
	if visited[root] {
		return "", nil, errors.New("recursive gitlink cycle rejected")
	}
	visited[root] = true
	defer delete(visited, root)

	scope := options.Scope
	if scope == "" {
		scope = ScopeFull
	}
	var inputs []scanInput
	switch scope {
	case ScopeFull, ScopeTracked:
		inputs, err = trackedAndWorktreeInputs(root, scope == ScopeFull, budget)
	case ScopeChanged:
		inputs, err = changedInputs(root, budget)
	case ScopePrePush:
		inputs, err = prePushInputs(root, options, budget)
	case ScopeFiles:
		if len(options.Files) == 0 {
			return "", nil, errors.New("files scope requires at least one --file")
		}
		inputs, err = explicitInputs(root, options.Files, budget)
	default:
		return "", nil, errors.New("unsupported source-safety scope")
	}
	if err != nil {
		return "", nil, err
	}

	for index := range inputs {
		before := len(inputs[index].data)
		classified := classifyInput(inputs[index])
		if expansionErr := budget.consumeExpansion(int64(len(classified.data) - before)); expansionErr != nil {
			return "", nil, expansionErr
		}
		inputs[index] = classified
	}
	if options.RecurseGitlinks {
		nested, nestedErr := recursiveGitlinkInputs(options, inputs, visited, budget)
		if nestedErr != nil {
			return "", nil, nestedErr
		}
		inputs = append(inputs, nested...)
	}
	return root, deduplicateInputs(inputs), nil
}

func resolveRepositoryRoot(requested string) (string, error) {
	start := requested
	if strings.TrimSpace(start) == "" {
		var err error
		start, err = os.Getwd()
		if err != nil {
			return "", safeError("resolve current directory", err)
		}
	}
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", safeError("resolve repository directory", err)
	}
	out, err := gitBytes(abs, "discover repository root", "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(string(out))
	if root == "" || strings.IndexByte(root, 0) >= 0 {
		return "", errors.New("Git returned an invalid repository root")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", safeError("resolve repository root", err)
	}
	return filepath.Clean(root), nil
}

func trackedAndWorktreeInputs(root string, includeUntracked bool, budget *scanBudget) ([]scanInput, error) {
	entries, err := allIndexEntries(root, budget)
	if err != nil {
		return nil, err
	}
	repository, err := os.OpenRoot(root)
	if err != nil {
		return nil, safeError("open repository root", err)
	}
	defer repository.Close()

	byPath := groupIndexEntries(entries)
	paths := sortedMapKeys(byPath)
	collector := inputCollector{inputs: make([]scanInput, 0, len(entries)+len(paths)), budget: budget}
	for _, path := range paths {
		pathEntries := byPath[path]
		for _, entry := range pathEntries {
			input, inputErr := inputFromIndex(root, entry)
			if inputErr != nil {
				return nil, inputErr
			}
			if addErr := collector.add(input); addErr != nil {
				return nil, addErr
			}
		}
		stageZero, ok := stageZeroEntry(pathEntries)
		if !ok {
			if addErr := collector.add(scanInput{
				path: path, variant: "index-state", kind: "unavailable", data: []byte("unmerged-index"),
			}); addErr != nil {
				return nil, addErr
			}
		}
		worktree, worktreeErr := inputForTrackedPath(root, repository, path, stageZero, ok)
		if worktreeErr != nil {
			return nil, worktreeErr
		}
		if addErr := collector.add(worktree); addErr != nil {
			return nil, addErr
		}
	}

	if includeUntracked {
		out, listErr := gitBytes(root, "list untracked paths", "ls-files", "--others", "--exclude-standard", "-z", "--")
		if listErr != nil {
			return nil, listErr
		}
		if metadataErr := budget.consumeMetadata(len(out)); metadataErr != nil {
			return nil, metadataErr
		}
		for _, path := range nulStrings(out) {
			input, inputErr := worktreeInput(repository, path, "worktree-untracked")
			if inputErr != nil {
				return nil, inputErr
			}
			if addErr := collector.add(input); addErr != nil {
				return nil, addErr
			}
		}
	}
	return collector.inputs, nil
}

func changedInputs(root string, budget *scanBudget) ([]scanInput, error) {
	entries, err := allIndexEntries(root, budget)
	if err != nil {
		return nil, err
	}
	byPath := groupIndexEntries(entries)
	stagedOutput, err := gitBytes(root, "list staged changes", "diff", "--no-ext-diff", "--cached", "--name-only", "--diff-filter=ACDMRTUXB", "-z", "--")
	if err != nil {
		return nil, err
	}
	unstagedOutput, err := gitBytes(root, "list worktree changes", "diff", "--no-ext-diff", "--name-only", "--diff-filter=ACDMRTUXB", "-z", "--")
	if err != nil {
		return nil, err
	}
	untrackedOutput, err := gitBytes(root, "list untracked paths", "ls-files", "--others", "--exclude-standard", "-z", "--")
	if err != nil {
		return nil, err
	}
	if metadataErr := budget.consumeMetadata(len(stagedOutput) + len(unstagedOutput) + len(untrackedOutput)); metadataErr != nil {
		return nil, metadataErr
	}

	collector := inputCollector{budget: budget}
	for _, path := range nulStrings(stagedOutput) {
		pathEntries := byPath[path]
		if len(pathEntries) == 0 {
			if addErr := collector.add(scanInput{path: path, variant: "index", kind: "absent", data: []byte("staged-deletion")}); addErr != nil {
				return nil, addErr
			}
			continue
		}
		for _, entry := range pathEntries {
			input, inputErr := inputFromIndex(root, entry)
			if inputErr != nil {
				return nil, inputErr
			}
			if addErr := collector.add(input); addErr != nil {
				return nil, addErr
			}
		}
	}

	repository, err := os.OpenRoot(root)
	if err != nil {
		return nil, safeError("open repository root", err)
	}
	defer repository.Close()
	worktreePaths := append(nulStrings(unstagedOutput), nulStrings(untrackedOutput)...)
	for _, path := range uniqueStrings(worktreePaths) {
		pathEntries := byPath[path]
		stageZero, ok := stageZeroEntry(pathEntries)
		input, inputErr := inputForTrackedPath(root, repository, path, stageZero, ok)
		if inputErr != nil {
			return nil, inputErr
		}
		if len(pathEntries) == 0 {
			input.variant = "worktree-untracked"
		}
		if addErr := collector.add(input); addErr != nil {
			return nil, addErr
		}
	}
	return collector.inputs, nil
}

func explicitInputs(root string, requested []string, budget *scanBudget) ([]scanInput, error) {
	repository, err := os.OpenRoot(root)
	if err != nil {
		return nil, safeError("open repository root", err)
	}
	defer repository.Close()
	collector := inputCollector{budget: budget}
	for _, raw := range requested {
		path, pathErr := canonicalPolicyPath(raw)
		if pathErr != nil {
			return nil, pathErr
		}
		input, inputErr := worktreeInput(repository, path, "worktree")
		if inputErr != nil {
			return nil, inputErr
		}
		if addErr := collector.add(input); addErr != nil {
			return nil, addErr
		}
	}
	return collector.inputs, nil
}

func inputForTrackedPath(root string, repository *os.Root, path string, entry indexEntry, hasStageZero bool) (scanInput, error) {
	if hasStageZero && entry.mode == "160000" {
		return gitlinkWorktreeInput(root, repository, entry)
	}
	return worktreeInput(repository, path, "worktree")
}

func worktreeInput(repository *os.Root, path string, variant string) (scanInput, error) {
	if !validGitPath(path) {
		return scanInput{}, errors.New("Git returned an unsafe repository path")
	}
	info, err := repository.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return scanInput{path: path, variant: variant, kind: "absent", data: []byte("absent")}, nil
	}
	if err != nil {
		return scanInput{}, safeError("inspect repository input", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, readErr := repository.Readlink(path)
		if readErr != nil {
			return scanInput{}, safeError("read repository symlink", readErr)
		}
		return scanInput{path: path, variant: variant, data: []byte(target), kind: "symlink"}, nil
	}
	if !info.Mode().IsRegular() {
		return scanInput{}, errors.New("repository input is not a regular file or symbolic link")
	}
	file, err := repository.Open(path)
	if err != nil {
		return scanInput{}, safeError("open repository input", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return scanInput{}, safeError("inspect opened repository input", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || info.Size() != openedInfo.Size() || !info.ModTime().Equal(openedInfo.ModTime()) {
		return scanInput{}, errors.New("repository input identity changed before descriptor open")
	}
	return readRegularDescriptor(path, variant, file, openedInfo, nil)
}

func readRegularDescriptor(path string, variant string, file *os.File, openedInfo os.FileInfo, afterRead func()) (scanInput, error) {
	if openedInfo.Size() > maxReviewBytes {
		return scanInput{path: path, variant: variant, data: []byte("artifact-exceeds-hard-review-limit"), kind: "unavailable"}, nil
	}
	hasher := sha256.New()
	var data []byte
	var readBytes int64
	var err error
	if openedInfo.Size() > maxTextBytes {
		readBytes, err = io.Copy(hasher, io.LimitReader(file, openedInfo.Size()+1))
	} else {
		var buffer bytes.Buffer
		readBytes, err = io.Copy(io.MultiWriter(&buffer, hasher), io.LimitReader(file, maxTextBytes+1))
		data = buffer.Bytes()
	}
	if err != nil {
		return scanInput{}, safeError("read repository input", err)
	}
	if afterRead != nil {
		afterRead()
	}
	after, err := file.Stat()
	if err != nil {
		return scanInput{}, safeError("inspect repository input after read", err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(openedInfo, after) || openedInfo.Mode() != after.Mode() || openedInfo.Size() != after.Size() ||
		!openedInfo.ModTime().Equal(after.ModTime()) || readBytes != after.Size() {
		return scanInput{}, errors.New("repository input changed during descriptor read")
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if openedInfo.Size() > maxTextBytes {
		return scanInput{path: path, variant: variant, digest: digest, kind: "non_text", nonTextReason: "size_limit"}, nil
	}
	return scanInput{path: path, variant: variant, data: data, digest: digest, kind: "text"}, nil
}

func gitlinkWorktreeInput(root string, repository *os.Root, entry indexEntry) (scanInput, error) {
	input := scanInput{path: entry.path, variant: "worktree", kind: "gitlink", data: []byte(entry.oid)}
	info, err := repository.Lstat(entry.path)
	if errors.Is(err, os.ErrNotExist) {
		input.gitlinkState = "uninitialized"
		return input, nil
	}
	if err != nil {
		return scanInput{}, safeError("inspect gitlink", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		input.gitlinkState = "invalid"
		input.data = []byte(entry.oid + "\ninvalid-worktree-type")
		return input, nil
	}
	subtree, err := repository.OpenRoot(entry.path)
	if err != nil {
		return scanInput{}, safeError("open gitlink root", err)
	}
	defer subtree.Close()
	if _, err := subtree.Lstat(".git"); errors.Is(err, os.ErrNotExist) {
		directory, openErr := subtree.Open(".")
		if openErr != nil {
			return scanInput{}, safeError("inspect uninitialized gitlink", openErr)
		}
		children, readErr := directory.ReadDir(2)
		closeErr := directory.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return scanInput{}, safeError("inspect uninitialized gitlink", readErr)
		}
		if closeErr != nil {
			return scanInput{}, safeError("close uninitialized gitlink", closeErr)
		}
		if len(children) == 0 {
			input.gitlinkState = "uninitialized"
			return input, nil
		}
		input.gitlinkState = "dirty"
		input.data = []byte(entry.oid + "\nnonempty-uninitialized-worktree")
		return input, nil
	} else if err != nil {
		return scanInput{}, safeError("inspect gitlink metadata", err)
	}

	canonical, canonicalErr := canonicalPolicyPath(entry.path)
	if canonicalErr != nil || canonical != entry.path {
		input.gitlinkState = "invalid"
		input.data = []byte(entry.oid + "\nnonportable-gitlink-path")
		return input, nil
	}
	gitlinkRoot := filepath.Join(root, filepath.FromSlash(canonical))
	resolvedGitlinkRoot, resolveRootErr := resolveRepositoryRoot(gitlinkRoot)
	if resolveRootErr != nil {
		input.gitlinkState = "invalid"
		input.data = []byte(entry.oid + "\nunreadable-gitlink-root")
		return input, nil
	}
	resolvedRootInfo, statRootErr := os.Stat(resolvedGitlinkRoot)
	if statRootErr != nil || !resolvedRootInfo.IsDir() || !os.SameFile(info, resolvedRootInfo) {
		input.gitlinkState = "invalid"
		input.data = []byte(entry.oid + "\nmismatched-gitlink-root")
		return input, nil
	}
	gitlinkRoot = resolvedGitlinkRoot
	headOutput, headErr := gitBytes(gitlinkRoot, "resolve gitlink HEAD", "rev-parse", "--verify", "HEAD^{commit}")
	if headErr != nil {
		input.gitlinkState = "invalid"
		input.data = []byte(entry.oid + "\nunreadable-gitlink-head")
		return input, nil
	}
	head := strings.ToLower(strings.TrimSpace(string(headOutput)))
	if !validObjectID(head) {
		input.gitlinkState = "invalid"
		input.data = []byte(entry.oid + "\ninvalid-gitlink-head")
		return input, nil
	}
	status, statusErr := gitBytes(gitlinkRoot, "inspect gitlink status", "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none")
	if statusErr != nil {
		input.gitlinkState = "invalid"
		input.data = []byte(entry.oid + "\nunreadable-gitlink-status")
		return input, nil
	}
	afterInfo, afterErr := repository.Lstat(entry.path)
	if afterErr != nil || !afterInfo.IsDir() || !os.SameFile(info, afterInfo) || !info.ModTime().Equal(afterInfo.ModTime()) {
		input.gitlinkState = "invalid"
		input.data = []byte(entry.oid + "\ngitlink-root-changed")
		return input, nil
	}
	dirty := len(status) != 0
	mismatch := !strings.EqualFold(head, entry.oid)
	switch {
	case dirty && mismatch:
		input.gitlinkState = "dirty_commit_mismatch"
	case dirty:
		input.gitlinkState = "dirty"
	case mismatch:
		input.gitlinkState = "commit_mismatch"
	default:
		input.gitlinkState = "clean"
		input.gitlinkRoot = gitlinkRoot
	}
	if dirty || mismatch {
		input.data = []byte(entry.oid + "\n" + head + "\n" + sha256Hex(status))
	}
	return input, nil
}

func recursiveGitlinkInputs(options Options, inputs []scanInput, visited map[string]bool, budget *scanBudget) ([]scanInput, error) {
	var nestedInputs []scanInput
	seenRoots := map[string]bool{}
	for _, input := range inputs {
		if input.kind != "gitlink" || input.gitlinkState != "clean" || input.gitlinkRoot == "" || seenRoots[input.gitlinkRoot] {
			continue
		}
		seenRoots[input.gitlinkRoot] = true
		nestedOptions := Options{Root: input.gitlinkRoot, Scope: ScopeFull, RecurseGitlinks: true}
		_, children, err := collectInputsVisited(nestedOptions, visited, budget)
		if err != nil {
			return nil, errors.New("recursive gitlink scan failed")
		}
		for _, child := range children {
			prefixBytes := int64(len(input.path) + 1 + len("gitlink/"))
			if expansionErr := budget.consumeExpansion(prefixBytes); expansionErr != nil {
				return nil, expansionErr
			}
			child.path = input.path + "/" + child.path
			child.variant = "gitlink/" + child.variant
			nestedInputs = append(nestedInputs, child)
		}
	}
	return nestedInputs, nil
}

func allIndexEntries(root string, budget *scanBudget) ([]indexEntry, error) {
	out, err := gitBytes(root, "read Git index", "ls-files", "--stage", "-z", "--")
	if err != nil {
		return nil, err
	}
	if metadataErr := budget.consumeMetadata(len(out)); metadataErr != nil {
		return nil, metadataErr
	}
	var entries []indexEntry
	for _, record := range nulRecords(out) {
		header, rawPath, ok := bytes.Cut(record, []byte{'\t'})
		fields := strings.Fields(string(header))
		if !ok || len(fields) != 3 || len(rawPath) == 0 {
			return nil, errors.New("Git index contains malformed metadata")
		}
		stage, parseErr := strconv.Atoi(fields[2])
		path := string(rawPath)
		if parseErr != nil || stage < 0 || stage > 3 || !validGitMode(fields[0]) || !validObjectID(fields[1]) || !validGitPath(path) {
			return nil, errors.New("Git index contains invalid metadata")
		}
		entries = append(entries, indexEntry{mode: fields[0], oid: strings.ToLower(fields[1]), stage: stage, path: path})
	}
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].path != entries[right].path {
			return entries[left].path < entries[right].path
		}
		return entries[left].stage < entries[right].stage
	})
	return entries, nil
}

func inputFromIndex(root string, entry indexEntry) (scanInput, error) {
	variant := "index"
	if entry.stage != 0 {
		variant = "index-stage-" + strconv.Itoa(entry.stage)
	}
	if allZero(entry.oid) {
		return scanInput{path: entry.path, variant: variant, kind: "unavailable", data: []byte("unresolved-index-object")}, nil
	}
	if entry.mode == "160000" {
		return scanInput{path: entry.path, variant: variant, data: []byte(entry.oid), kind: "gitlink", gitlinkState: "index"}, nil
	}
	kind := "text"
	if entry.mode == "120000" {
		kind = "symlink"
	}
	return gitBlobInput(root, entry.path, variant, entry.oid, kind)
}

func prePushInputs(root string, options Options, budget *scanBudget) ([]scanInput, error) {
	shallow, err := gitBytes(root, "inspect repository history completeness", "rev-parse", "--is-shallow-repository")
	if err != nil {
		return nil, err
	}
	if metadataErr := budget.consumeMetadata(len(shallow)); metadataErr != nil {
		return nil, metadataErr
	}
	if strings.TrimSpace(string(shallow)) != "false" {
		return nil, errors.New("pre-push source-safety requires complete non-shallow history")
	}
	updates := options.PushUpdates
	if updates == nil {
		if strings.TrimSpace(options.Base) == "" {
			return nil, errors.New("pre-push scope requires --base")
		}
		updates = []PushUpdate{{LocalOID: options.Head, RemoteOID: options.Base}}
	}
	commitSet := map[string]bool{}
	collector := inputCollector{budget: budget}
	objectCache := map[string]publishedObject{}
	scannedTags := map[string]bool{}
	var targetRemoteExclusions []string
	remoteLoaded := false
	for _, update := range updates {
		headRevision := strings.TrimSpace(update.LocalOID)
		if headRevision == "" {
			headRevision = "HEAD"
		}
		if isZeroOID(headRevision) {
			continue // Remote ref deletion publishes no new object.
		}
		head, err := resolvePublishedHead(root, headRevision, budget, &collector, objectCache, scannedTags)
		if err != nil {
			return nil, err
		}
		baseRevision := strings.TrimSpace(update.RemoteOID)
		if baseRevision == "" {
			return nil, errors.New("pre-push update is missing a remote object identity")
		}
		var exclusions []string
		if isZeroOID(baseRevision) {
			if len(options.RemoteRefs) != 0 && options.RemoteName == "" {
				return nil, errors.New("exact remote refs require a verified target remote")
			}
			if options.RemoteName != "" {
				if !remoteLoaded {
					targetRemoteExclusions, err = remoteCommitExclusions(root, options.RemoteName, options.RemoteURLSHA256, options.RemoteRefs, budget)
					if err != nil {
						return nil, err
					}
					remoteLoaded = true
				}
				exclusions = append(exclusions, targetRemoteExclusions...)
			}
		} else {
			base, resolveErr := resolveCommit(root, baseRevision)
			if resolveErr != nil {
				return nil, errors.New("resolve pre-push base failed")
			}
			exclusions = append(exclusions, base)
		}
		args := []string{"rev-list", head}
		if len(exclusions) != 0 {
			args = append(args, "--not")
			args = append(args, exclusions...)
		}
		out, listErr := gitBytes(root, "enumerate pre-push history", args...)
		if listErr != nil {
			return nil, listErr
		}
		if metadataErr := budget.consumeMetadata(len(out)); metadataErr != nil {
			return nil, metadataErr
		}
		for _, commit := range strings.Fields(string(out)) {
			if !validObjectID(commit) {
				return nil, errors.New("Git returned an invalid history object identity")
			}
			commit = strings.ToLower(commit)
			if !commitSet[commit] {
				if commitErr := budget.consumeCommit(); commitErr != nil {
					return nil, commitErr
				}
				commitSet[commit] = true
			}
		}
	}

	commits := sortedBoolMapKeys(commitSet)
	for _, commit := range commits {
		metadata, metadataErr := commitMetadataInput(root, commit, budget)
		if metadataErr != nil {
			return nil, metadataErr
		}
		if addErr := collector.add(metadata); addErr != nil {
			return nil, addErr
		}
		pathsOutput, err := gitBytes(root, "enumerate commit changes", "diff-tree", "--no-ext-diff", "-m", "--root", "--no-commit-id", "--name-only", "-z", "-r", "--diff-filter=ACMRTUXB", commit)
		if err != nil {
			return nil, err
		}
		if metadataErr := budget.consumeMetadata(len(pathsOutput)); metadataErr != nil {
			return nil, metadataErr
		}
		paths := nulStrings(pathsOutput)
		if len(paths) == 0 {
			continue
		}
		tree, treeErr := commitTreeEntries(root, commit, budget)
		if treeErr != nil {
			return nil, treeErr
		}
		for _, path := range paths {
			entry, ok := tree[path]
			if !ok {
				continue // A deletion has no newly published content in this commit.
			}
			input, inputErr := inputFromTree(root, entry)
			if inputErr != nil {
				return nil, inputErr
			}
			input.variant = "commit"
			if addErr := collector.add(input); addErr != nil {
				return nil, addErr
			}
		}
	}
	return collector.inputs, nil
}

func resolvePublishedHead(root string, revision string, budget *scanBudget, collector *inputCollector, cache map[string]publishedObject, scannedTags map[string]bool) (string, error) {
	start, err := resolveObject(root, revision, budget)
	if err != nil {
		return "", errors.New("resolve pre-push object failed")
	}
	inspect := func(oid string) (publishedObject, error) {
		return inspectPublishedObject(root, oid, budget, cache)
	}
	consumeTag := func(oid string, metadata []byte) error {
		if scannedTags[oid] {
			return nil
		}
		input := scanInput{
			path:    "tag-metadata/" + sha256Hex([]byte(strings.ToLower(oid))),
			variant: "tag-metadata",
			data:    metadata,
		}
		if err := collector.add(input); err != nil {
			return err
		}
		scannedTags[oid] = true
		return nil
	}
	return walkPublishedObject(start, inspect, consumeTag)
}

func resolveObject(root string, revision string, budget *scanBudget) (string, error) {
	revision = strings.TrimSpace(revision)
	if revision == "" || strings.IndexByte(revision, 0) >= 0 || strings.HasPrefix(revision, "-") {
		return "", errors.New("invalid revision")
	}
	if validObjectID(revision) && !allZero(revision) {
		return strings.ToLower(revision), nil
	}
	out, err := gitBytes(root, "resolve object", "rev-parse", "--verify", "--end-of-options", revision)
	if err != nil {
		return "", err
	}
	if metadataErr := budget.consumeMetadata(len(out)); metadataErr != nil {
		return "", metadataErr
	}
	fields := strings.Fields(string(out))
	if len(fields) != 1 || !validObjectID(fields[0]) || allZero(fields[0]) {
		return "", errors.New("Git returned an invalid object identity")
	}
	return strings.ToLower(fields[0]), nil
}

func inspectPublishedObject(root string, oid string, budget *scanBudget, cache map[string]publishedObject) (publishedObject, error) {
	if !validObjectID(oid) || allZero(oid) {
		return publishedObject{}, errors.New("invalid published object identity")
	}
	oid = strings.ToLower(oid)
	if cached, ok := cache[oid]; ok {
		return cached, nil
	}
	typeOutput, err := gitBytes(root, "inspect published object type", "cat-file", "-t", oid)
	if err != nil {
		return publishedObject{}, err
	}
	if metadataErr := budget.consumeMetadata(len(typeOutput)); metadataErr != nil {
		return publishedObject{}, metadataErr
	}
	fields := strings.Fields(string(typeOutput))
	if len(fields) != 1 {
		return publishedObject{}, errors.New("Git returned an invalid object type")
	}
	object := publishedObject{objectType: fields[0]}
	if object.objectType == "tag" {
		object.data, err = gitBytes(root, "read annotated tag metadata", "cat-file", "tag", oid)
		if err != nil {
			return publishedObject{}, err
		}
		if metadataErr := budget.consumeMetadata(len(object.data)); metadataErr != nil {
			return publishedObject{}, metadataErr
		}
	}
	cache[oid] = object
	return object, nil
}

func walkPublishedObject(start string, inspect func(string) (publishedObject, error), consumeTag func(string, []byte) error) (string, error) {
	current := strings.ToLower(start)
	expectedType := ""
	visited := map[string]bool{}
	tagDepth := 0
	for {
		if !validObjectID(current) || allZero(current) {
			return "", errors.New("annotated tag contains an invalid target identity")
		}
		if visited[current] {
			return "", errors.New("annotated tag chain contains a cycle")
		}
		visited[current] = true
		object, err := inspect(current)
		if err != nil {
			return "", err
		}
		if expectedType != "" && object.objectType != expectedType {
			return "", errors.New("annotated tag target type does not match the target object")
		}
		switch object.objectType {
		case "commit":
			return current, nil
		case "tag":
			if tagDepth >= maxAnnotatedTagDepth {
				return "", errors.New("annotated tag chain exceeds the source-safety depth limit")
			}
			target, targetType, parseErr := annotatedTagTarget(object.data)
			if parseErr != nil {
				return "", parseErr
			}
			if consumeTag != nil {
				if consumeErr := consumeTag(current, object.data); consumeErr != nil {
					return "", consumeErr
				}
			}
			tagDepth++
			current = target
			expectedType = targetType
		default:
			return "", errors.New("pre-push update references an unsupported Git object type")
		}
	}
}

func annotatedTagTarget(metadata []byte) (string, string, error) {
	headerEnd := bytes.Index(metadata, []byte("\n\n"))
	if headerEnd <= 0 {
		return "", "", errors.New("annotated tag contains invalid metadata")
	}
	objectLine, remainder, ok := bytes.Cut(metadata[:headerEnd], []byte{'\n'})
	if !ok {
		return "", "", errors.New("annotated tag contains invalid metadata")
	}
	typeLine, remainder, ok := bytes.Cut(remainder, []byte{'\n'})
	if !ok {
		return "", "", errors.New("annotated tag contains invalid metadata")
	}
	tagLine := remainder
	if line, _, found := bytes.Cut(remainder, []byte{'\n'}); found {
		tagLine = line
	}
	if len(objectLine) > maxAnnotatedTagHeaderLineBytes || len(typeLine) > maxAnnotatedTagHeaderLineBytes || len(tagLine) > maxAnnotatedTagHeaderLineBytes {
		return "", "", errors.New("annotated tag header exceeds the source-safety limit")
	}
	objectFields := strings.Fields(string(objectLine))
	typeFields := strings.Fields(string(typeLine))
	tagFields := strings.Fields(string(tagLine))
	if len(objectFields) != 2 || objectFields[0] != "object" || !validObjectID(objectFields[1]) || allZero(objectFields[1]) ||
		len(typeFields) != 2 || typeFields[0] != "type" || len(tagFields) < 2 || tagFields[0] != "tag" {
		return "", "", errors.New("annotated tag contains invalid metadata")
	}
	switch typeFields[1] {
	case "commit", "tag", "tree", "blob":
	default:
		return "", "", errors.New("annotated tag contains an unsupported target type")
	}
	return strings.ToLower(objectFields[1]), typeFields[1], nil
}

func commitMetadataInput(root string, commit string, budget *scanBudget) (scanInput, error) {
	if !validObjectID(commit) || allZero(commit) {
		return scanInput{}, errors.New("invalid commit object identity")
	}
	metadata, err := gitBytes(root, "read commit metadata", "cat-file", "commit", commit)
	if err != nil {
		return scanInput{}, err
	}
	if metadataErr := budget.consumeMetadata(len(metadata)); metadataErr != nil {
		return scanInput{}, metadataErr
	}
	return scanInput{
		path:    "commit-metadata/" + sha256Hex([]byte(strings.ToLower(commit))),
		variant: "commit-metadata",
		data:    metadata,
	}, nil
}

func commitTreeEntries(root string, commit string, budget *scanBudget) (map[string]treeEntry, error) {
	out, err := gitBytes(root, "read commit tree", "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return nil, err
	}
	if metadataErr := budget.consumeMetadata(len(out)); metadataErr != nil {
		return nil, metadataErr
	}
	entries := make(map[string]treeEntry)
	for _, record := range nulRecords(out) {
		header, rawPath, ok := bytes.Cut(record, []byte{'\t'})
		fields := strings.Fields(string(header))
		path := string(rawPath)
		if !ok || len(fields) != 3 || !validGitMode(fields[0]) || !validObjectID(fields[2]) || !validGitPath(path) {
			return nil, errors.New("Git tree contains invalid metadata")
		}
		entries[path] = treeEntry{mode: fields[0], objectType: fields[1], oid: strings.ToLower(fields[2]), path: path}
	}
	return entries, nil
}

func inputFromTree(root string, entry treeEntry) (scanInput, error) {
	if entry.mode == "160000" && entry.objectType == "commit" {
		return scanInput{path: entry.path, data: []byte(entry.oid), kind: "gitlink", gitlinkState: "commit"}, nil
	}
	if entry.objectType != "blob" {
		return scanInput{}, errors.New("Git tree contains an unsupported object type")
	}
	kind := "text"
	if entry.mode == "120000" {
		kind = "symlink"
	}
	return gitBlobInput(root, entry.path, "", entry.oid, kind)
}

func gitBlobInput(root string, path string, variant string, oid string, kind string) (scanInput, error) {
	sizeOutput, err := gitBytes(root, "inspect Git blob size", "cat-file", "-s", oid)
	if err != nil {
		return scanInput{}, err
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(sizeOutput)), 10, 64)
	if err != nil || size < 0 {
		return scanInput{}, errors.New("Git returned an invalid blob size")
	}
	if size > maxReviewBytes {
		return scanInput{path: path, variant: variant, data: []byte("blob-exceeds-hard-review-limit"), kind: "unavailable"}, nil
	}
	data, digest, err := readGitBlob(root, oid, size, size <= maxTextBytes)
	if err != nil {
		return scanInput{}, err
	}
	if size > maxTextBytes {
		return scanInput{path: path, variant: variant, digest: digest, kind: "non_text", nonTextReason: "size_limit"}, nil
	}
	return scanInput{path: path, variant: variant, data: data, digest: digest, kind: kind}, nil
}

func readGitBlob(root string, oid string, expectedSize int64, capture bool) ([]byte, string, error) {
	// #nosec G204 -- the object identity is validated Git metadata and no shell is involved.
	command := exec.Command("git", "-C", root, "cat-file", "blob", oid)
	command.Env = hardenedGitEnvironment()
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, "", safeError("open Git blob stream", err)
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return nil, "", safeError("start Git blob stream", err)
	}
	hasher := sha256.New()
	var buffer bytes.Buffer
	writer := io.Writer(hasher)
	if capture {
		writer = io.MultiWriter(&buffer, hasher)
	}
	written, copyErr := io.Copy(writer, io.LimitReader(stdout, expectedSize+1))
	if copyErr != nil || written != expectedSize {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if copyErr != nil || waitErr != nil || written != expectedSize {
		return nil, "", errors.New("read Git blob stream failed")
	}
	return buffer.Bytes(), hex.EncodeToString(hasher.Sum(nil)), nil
}

func remoteCommitExclusions(root string, remoteName string, actualURLDigest string, selectedRefs []string, budget *scanBudget) ([]string, error) {
	if !safeRemoteName(remoteName) {
		return nil, errors.New("target remote name is invalid")
	}
	if len(actualURLDigest) != 64 || !isHex(actualURLDigest) {
		return nil, nil
	}
	if len(selectedRefs) > maxSourceInputs {
		return nil, errors.New("exact target-remote refs exceed the source-safety policy budget")
	}
	requested := map[string]bool{}
	for _, remoteRef := range selectedRefs {
		if !validRemoteRefName(remoteRef) || requested[remoteRef] {
			return nil, errors.New("exact target-remote ref selection is invalid")
		}
		requested[remoteRef] = true
	}
	fetchURL, fetchErr := configuredRemoteURL(root, remoteName, false)
	pushURL, pushErr := configuredRemoteURL(root, remoteName, true)
	defer zeroBytes(fetchURL)
	defer zeroBytes(pushURL)
	if fetchErr != nil || pushErr != nil || !strings.EqualFold(sha256Hex(fetchURL), actualURLDigest) || !strings.EqualFold(sha256Hex(pushURL), actualURLDigest) {
		// If the Git-provided target does not exactly match both the URL queried by
		// ls-remote and the configured push target, exclusions cannot be proven.
		// Scanning all reachable history is conservative and cannot weaken safety.
		return nil, nil
	}
	if !remoteURLSafeForHelper(fetchURL) {
		// Git transport helpers receive the expanded URL in their own argv. Never
		// start a second transport process for userinfo, signed-query, or SCP-style
		// URLs; scan all history instead so credentials/private targets are not
		// duplicated into descendant process metadata.
		return nil, nil
	}
	out, err := gitBytes(root, "query exact target remote", "ls-remote", "--refs", "--", remoteName)
	if err != nil {
		return nil, errors.New("query exact target remote failed")
	}
	if metadataErr := budget.consumeMetadata(len(out)); metadataErr != nil {
		return nil, metadataErr
	}
	set := map[string]bool{}
	found := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !validObjectID(fields[0]) || !strings.HasPrefix(fields[1], "refs/") {
			return nil, errors.New("target remote returned invalid ref metadata")
		}
		if len(requested) != 0 && !requested[fields[1]] {
			continue
		}
		found[fields[1]] = true
		resolved, resolveErr := resolveCommit(root, fields[0])
		if resolveErr != nil {
			// An unrelated remote object may not be present locally. Not excluding it
			// is conservative: it can only increase the history that is scanned.
			continue
		}
		set[resolved] = true
	}
	for remoteRef := range requested {
		if !found[remoteRef] {
			return nil, errors.New("exact target-remote ref was not advertised")
		}
	}
	return sortedBoolMapKeys(set), nil
}

func validRemoteRefName(value string) bool {
	return strings.HasPrefix(value, "refs/") && len(value) <= 1024 && !strings.ContainsAny(value, "\x00\r\n\t ~^:?*[\\") && !strings.Contains(value, "..") && !strings.HasSuffix(value, "/")
}

func configuredRemoteURL(root string, remoteName string, push bool) ([]byte, error) {
	args := []string{"remote", "get-url"}
	if push {
		args = append(args, "--push")
	}
	args = append(args, remoteName)
	out, err := gitBytes(root, "resolve configured target remote", args...)
	if err != nil {
		return nil, err
	}
	out = bytes.TrimSuffix(out, []byte{'\n'})
	out = bytes.TrimSuffix(out, []byte{'\r'})
	if len(out) == 0 || bytes.IndexAny(out, "\x00\r\n") >= 0 {
		return nil, errors.New("configured target remote URL is invalid")
	}
	return out, nil
}

func remoteURLSafeForHelper(raw []byte) bool {
	value := string(raw)
	if strings.Contains(value, "@") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "" || drivePrefixedPath(value) {
		return true
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https", "ssh", "git", "file":
		return true
	default:
		return false
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func safeRemoteName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._-", character))) {
			return false
		}
	}
	return true
}

func resolveCommit(root string, revision string) (string, error) {
	if revision == "" || strings.IndexByte(revision, 0) >= 0 || strings.HasPrefix(revision, "-") {
		return "", errors.New("invalid revision")
	}
	out, err := gitBytes(root, "resolve commit", "rev-parse", "--verify", "--end-of-options", revision+"^{commit}")
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(string(out))
	if !validObjectID(commit) || allZero(commit) {
		return "", errors.New("Git returned an invalid commit identity")
	}
	return strings.ToLower(commit), nil
}

func isZeroOID(value string) bool {
	return (len(value) == 40 || len(value) == 64) && allZero(value)
}

func allZero(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character != '0' {
			return false
		}
	}
	return true
}

func validObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
			return false
		}
	}
	return true
}

func validGitMode(mode string) bool {
	switch mode {
	case "100644", "100755", "120000", "160000":
		return true
	default:
		return false
	}
}

func validGitPath(path string) bool {
	if path == "" || strings.IndexByte(path, 0) >= 0 || strings.HasPrefix(path, "/") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func gitBytes(root string, operation string, args ...string) ([]byte, error) {
	// #nosec G204 -- Git receives a validated argument vector directly; no shell is involved.
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = hardenedGitEnvironment()
	stdout := cappedBuffer{limit: maxGitMetadataBytes}
	command.Stdout = &stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, safeError(operation, err)
	}
	if stdout.exceeded {
		return nil, errors.New("Git metadata output exceeds the source-safety limit")
	}
	return stdout.buffer.Bytes(), nil
}

func hardenedGitEnvironment() []string {
	return append(os.Environ(),
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=Never",
	)
}

func nulRecords(output []byte) [][]byte {
	parts := bytes.Split(output, []byte{0})
	result := make([][]byte, 0, len(parts))
	for _, part := range parts {
		if len(part) != 0 {
			result = append(result, part)
		}
	}
	return result
}

func nulStrings(output []byte) []string {
	values := make([]string, 0)
	for _, record := range nulRecords(output) {
		values = append(values, string(record))
	}
	return uniqueStrings(values)
}

func groupIndexEntries(entries []indexEntry) map[string][]indexEntry {
	result := make(map[string][]indexEntry)
	for _, entry := range entries {
		result[entry.path] = append(result[entry.path], entry)
	}
	return result
}

func stageZeroEntry(entries []indexEntry) (indexEntry, bool) {
	for _, entry := range entries {
		if entry.stage == 0 {
			return entry, true
		}
	}
	return indexEntry{}, false
}

func sortedMapKeys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedBoolMapKeys(values map[string]bool) []string {
	return sortedMapKeys(values)
}

func uniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for index, value := range values {
		if index == 0 || value != values[index-1] {
			result = append(result, value)
		}
	}
	return result
}

func deduplicateInputs(inputs []scanInput) []scanInput {
	sort.Slice(inputs, func(left, right int) bool {
		if inputs[left].path != inputs[right].path {
			return inputs[left].path < inputs[right].path
		}
		if inputs[left].variant != inputs[right].variant {
			return inputs[left].variant < inputs[right].variant
		}
		if inputs[left].gitlinkState != inputs[right].gitlinkState {
			return inputs[left].gitlinkState < inputs[right].gitlinkState
		}
		return inputs[left].digest < inputs[right].digest
	})
	result := inputs[:0]
	last := ""
	for _, input := range inputs {
		key := input.path + "\x00" + input.variant + "\x00" + input.kind + "\x00" + input.gitlinkState + "\x00" + input.digest
		if key != last {
			result = append(result, input)
			last = key
		}
	}
	return result
}
