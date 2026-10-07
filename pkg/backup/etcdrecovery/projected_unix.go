// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package etcdrecovery

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// readProjectedBytes accepts only Kubernetes atomic-writer mounts with one
// exact ..data link, one in-root generation directory, and allowlisted visible
// key links. The resolved file is still opened and revalidated as a bounded
// regular file; arbitrary symlinks and path escapes remain rejected.
func readProjectedBytes(root, name string, allowed []string, maximum int64) ([]byte, error) {
	return readProjectedBytesContext(context.Background(), root, name, allowed, maximum)
}

func readProjectedBytesContext(ctx context.Context, root, name string, allowed []string, maximum int64) ([]byte, error) {
	optional := make([]string, 0, len(allowed))
	found := false
	for _, value := range allowed {
		if value == name {
			found = true
			continue
		}
		optional = append(optional, value)
	}
	if !found {
		return nil, errors.New("projected input is not allowlisted")
	}
	values, err := readProjectedSetContext(ctx, root, []string{name}, optional, maximum)
	if err != nil {
		return nil, err
	}
	return values[name], nil
}

func readProjectedSetContext(ctx context.Context, root string, required, optional []string, maximum int64) (map[string][]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("projected input context is invalid")
	}
	cleanRoot := filepath.Clean(root)
	if !filepath.IsAbs(cleanRoot) || cleanRoot != root || maximum < 1 {
		return nil, errors.New("projected input path is invalid")
	}
	resolvedRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil || resolvedRoot != cleanRoot {
		return nil, errors.New("projected input root contains a link")
	}
	ordered := make([]string, 0, len(required)+len(optional))
	allowedSet := make(map[string]bool, cap(ordered))
	requiredSet := make(map[string]bool, len(required))
	for _, value := range append(append([]string(nil), required...), optional...) {
		if !safeProjectedName(value) || allowedSet[value] {
			return nil, errors.New("projected input allowlist is invalid")
		}
		allowedSet[value] = true
		ordered = append(ordered, value)
	}
	for _, value := range required {
		requiredSet[value] = true
	}
	rootInfo, err := os.Lstat(cleanRoot)
	if err != nil || !validProjectedDirectory(rootInfo) {
		return nil, errors.New("projected input root is invalid")
	}
	dataTarget, err := os.Readlink(filepath.Join(cleanRoot, "..data"))
	if err != nil || !validGenerationName(dataTarget) {
		return nil, errors.New("projected input generation link is invalid")
	}
	generationPath := filepath.Join(cleanRoot, dataTarget)
	generationInfo, err := os.Lstat(generationPath)
	if err != nil || !validProjectedDirectory(generationInfo) {
		return nil, errors.New("projected input generation is invalid")
	}
	entries, err := os.ReadDir(cleanRoot)
	if err != nil {
		return nil, errors.New("read projected input root")
	}
	seenGeneration := false
	visible := make(map[string]string, len(allowedSet))
	for _, entry := range entries {
		entryName := entry.Name()
		switch {
		case entryName == "..data":
			continue
		case entryName == dataTarget && entry.IsDir():
			seenGeneration = true
		case allowedSet[entryName]:
			target, linkErr := os.Readlink(filepath.Join(cleanRoot, entryName))
			if linkErr != nil || target != filepath.Join("..data", entryName) {
				return nil, errors.New("projected input visible link is invalid")
			}
			visible[entryName] = target
		default:
			return nil, errors.New("projected input root contains an unexpected entry")
		}
	}
	if !seenGeneration {
		return nil, errors.New("projected input generation is absent")
	}
	generationEntries, err := os.ReadDir(generationPath)
	if err != nil || len(generationEntries) == 0 {
		return nil, errors.New("projected input generation is empty")
	}
	present := make(map[string]bool, len(generationEntries))
	for _, entry := range generationEntries {
		if !allowedSet[entry.Name()] || entry.IsDir() {
			return nil, errors.New("projected input generation contains an unexpected entry")
		}
		if _, ok := visible[entry.Name()]; !ok {
			return nil, errors.New("projected input generation contains an unprojected key")
		}
		present[entry.Name()] = true
	}
	for name := range requiredSet {
		if !present[name] {
			return nil, errors.New("projected input required key is absent")
		}
	}
	if len(visible) != len(present) {
		return nil, errors.New("projected input visible keys differ from generation")
	}
	values := make(map[string][]byte, len(present))
	clearValues := func() {
		for _, payload := range values {
			clear(payload)
		}
	}
	for _, name := range ordered {
		if !present[name] {
			continue
		}
		payload, readErr := readProtectedBytesWithPolicy(ctx, filepath.Join(generationPath, name), maximum, currentOrRootReadOnly)
		if readErr != nil {
			clearValues()
			return nil, readErr
		}
		values[name] = payload
	}
	dataTargetAfter, dataErr := os.Readlink(filepath.Join(cleanRoot, "..data"))
	rootAfter, rootErr := os.Lstat(cleanRoot)
	generationAfter, generationErr := os.Lstat(generationPath)
	if dataErr != nil || dataTargetAfter != dataTarget || rootErr != nil || generationErr != nil ||
		!sameFileMetadata(rootInfo, rootAfter) || !sameFileMetadata(generationInfo, generationAfter) {
		clearValues()
		return nil, errors.New("projected input changed while reading")
	}
	for name, target := range visible {
		visibleAfter, visibleErr := os.Readlink(filepath.Join(cleanRoot, name))
		if visibleErr != nil || visibleAfter != target {
			clearValues()
			return nil, errors.New("projected input changed while reading")
		}
	}
	return values, nil
}

func readProtectedBytesWithPolicy(ctx context.Context, path string, maximum int64, policy filePolicy) ([]byte, error) {
	opened, err := openProtectedFile(path, maximum, policy)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	data := make([]byte, opened.initial.Size())
	if _, err := io.ReadFull(&protectedContextReader{ctx: ctx, reader: opened.file}, data); err != nil || opened.ValidateStable() != nil {
		clear(data)
		return nil, errors.New("read projected input")
	}
	return data, nil
}

func safeProjectedName(value string) bool {
	return value != "" && value == filepath.Base(value) && value != "." && value != ".." && !strings.HasPrefix(value, "..") && !strings.ContainsAny(value, "/\\\x00")
}

func validGenerationName(value string) bool {
	return strings.HasPrefix(value, "..") && value != ".." && value != "..data" && value != "..data_tmp" &&
		value == filepath.Base(value) && !strings.ContainsAny(value, "/\\\x00")
}

func validProjectedDirectory(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir() &&
		info.Mode().Perm()&0o022 == 0 && ownedByCurrentOrRoot(info)
}
