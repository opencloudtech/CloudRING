// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type parentRootPath struct {
	root *os.Root
	name string
}

type operatorSelectedInput struct {
	canonicalPath string
	resolvedPath  string
	opaqueID      string
	data          []byte
	contentDigest [sha256.Size]byte
	rooted        parentRootPath
	file          *os.File
	fileInfo      os.FileInfo
	readErr       error
}

type evidenceInputGuard struct {
	evidencePath string
	inputs       []*operatorSelectedInput
}

func openOperatorSelectedInput(path string) *operatorSelectedInput {
	input := &operatorSelectedInput{}
	canonical, canonicalErr := canonicalOperatorPath(path)
	selectionKey := path
	if canonicalErr == nil {
		input.canonicalPath = canonical
		selectionKey = canonical
	}
	input.opaqueID = opaqueInputIdentity(selectionKey, nil)
	if canonicalErr != nil {
		input.readErr = errors.New("selected connector package path is unavailable")
		return input
	}

	resolved, err := resolveAliasPath(canonical)
	if err != nil {
		input.readErr = errors.New("selected connector package path cannot be resolved safely")
		return input
	}
	input.resolvedPath = resolved

	rooted, err := openParentRootPath(canonical)
	if err != nil {
		input.readErr = errors.New("selected connector package is unavailable")
		return input
	}
	input.rooted = rooted
	file, err := rooted.root.Open(rooted.name)
	if err != nil {
		return input.fail(errors.New("selected connector package is unavailable"))
	}
	input.file = file
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return input.fail(errors.New("selected connector package is not a readable regular file"))
	}
	input.fileInfo = info
	data, err := io.ReadAll(file)
	if err != nil {
		return input.fail(errors.New("selected connector package could not be read"))
	}
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) || current.Size() != int64(len(data)) {
		return input.fail(errors.New("selected connector package changed while it was read"))
	}
	input.data = data
	input.contentDigest = sha256.Sum256(data)
	input.opaqueID = opaqueInputIdentity(selectionKey, data)
	return input
}

func (input *operatorSelectedInput) fail(primary error) *operatorSelectedInput {
	input.readErr = errors.Join(primary, input.close())
	return input
}

func (input *operatorSelectedInput) close() (resultErr error) {
	if input == nil {
		return nil
	}
	if input.file != nil {
		if err := input.file.Close(); err != nil {
			resultErr = errors.Join(resultErr, errors.New("close selected connector package"))
		}
		input.file = nil
	}
	var closeRootErr error
	input.rooted.close(&closeRootErr)
	if closeRootErr != nil {
		resultErr = errors.Join(resultErr, errors.New("close selected connector package parent"))
	}
	return resultErr
}

func (input *operatorSelectedInput) verifyStable() error {
	if input == nil || input.readErr != nil || input.file == nil || input.rooted.root == nil || input.fileInfo == nil {
		return nil
	}
	openInfo, err := input.file.Stat()
	if err != nil || !os.SameFile(input.fileInfo, openInfo) || openInfo.Size() != int64(len(input.data)) {
		return errors.New("selected connector package changed before evidence publication")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.NewSectionReader(input.file, 0, int64(len(input.data)))); err != nil {
		return errors.New("selected connector package could not be revalidated before evidence publication")
	}
	var currentDigest [sha256.Size]byte
	copy(currentDigest[:], digest.Sum(nil))
	if currentDigest != input.contentDigest {
		return errors.New("selected connector package contents changed before evidence publication")
	}
	openInfoAfterRead, err := input.file.Stat()
	if err != nil || !os.SameFile(input.fileInfo, openInfoAfterRead) || openInfoAfterRead.Size() != int64(len(input.data)) {
		return errors.New("selected connector package changed during evidence pre-publication validation")
	}
	selectedInfo, err := input.rooted.root.Stat(input.rooted.name)
	if err != nil || !os.SameFile(input.fileInfo, selectedInfo) {
		return errors.New("selected connector package path changed before evidence publication")
	}
	return nil
}

func opaqueInputIdentity(selection string, data []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("ocsctl-input-v1\x00"))
	_, _ = digest.Write([]byte(normalizePathForComparison(selection)))
	_, _ = digest.Write([]byte{0})
	if data != nil {
		content := sha256.Sum256(data)
		_, _ = digest.Write(content[:])
	} else {
		_, _ = digest.Write([]byte("unreadable"))
	}
	return "input-sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func newEvidenceInputGuard(evidencePath string, inputs []*operatorSelectedInput) (*evidenceInputGuard, error) {
	canonical, err := canonicalOperatorPath(evidencePath)
	if err != nil {
		return nil, errors.New("evidence destination cannot be resolved safely")
	}
	guard := &evidenceInputGuard{evidencePath: canonical, inputs: inputs}
	if err := guard.verify(); err != nil {
		return nil, err
	}
	return guard, nil
}

func (guard *evidenceInputGuard) verify() error {
	if guard == nil {
		return nil
	}
	evidenceResolved, err := resolveAliasPath(guard.evidencePath)
	if err != nil {
		return errors.New("cannot prove that the evidence destination is separate from connector package inputs")
	}
	// statWithinParent resolves the operator-selected final component through an
	// os.Root confined to its canonical parent. It follows an in-parent
	// symlink/reparse target for SameFile checks but cannot traverse outside that
	// parent namespace.
	evidenceInfo, statErr := statWithinParent(guard.evidencePath)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("cannot inspect the evidence destination safely")
	}
	for _, input := range guard.inputs {
		if input == nil {
			continue
		}
		if input.canonicalPath == "" || input.resolvedPath == "" {
			return errors.New("cannot prove that the evidence destination is separate from connector package inputs")
		}
		if sameCanonicalPath(guard.evidencePath, input.canonicalPath) || sameCanonicalPath(evidenceResolved, input.resolvedPath) {
			return errors.New("evidence destination aliases a connector package input")
		}
		if err := input.verifyStable(); err != nil {
			return err
		}
		if statErr == nil && input.fileInfo != nil && os.SameFile(evidenceInfo, input.fileInfo) {
			return errors.New("evidence destination aliases a connector package input")
		}
	}
	return nil
}

func canonicalOperatorPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absolute), nil
}

// resolveAliasPath follows every existing symlink/reparse component and keeps
// any not-yet-created suffix lexical. That lets collision checks cover both an
// existing destination and a destination below a path that will be created.
func resolveAliasPath(path string) (string, error) {
	canonical, err := canonicalOperatorPath(path)
	if err != nil {
		return "", err
	}
	current := canonical
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			resolved, err = canonicalOperatorPath(resolved)
			if err != nil {
				return "", err
			}
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func sameCanonicalPath(left string, right string) bool {
	if left == "" || right == "" {
		return false
	}
	return normalizePathForComparison(filepath.Clean(left)) == normalizePathForComparison(filepath.Clean(right))
}

func normalizePathForComparison(path string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

func openParentRootPath(path string) (parentRootPath, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return parentRootPath{}, fmt.Errorf("resolve absolute path: %w", err)
	}
	absolute = filepath.Clean(absolute)
	parent := filepath.Dir(absolute)
	name := filepath.Base(absolute)
	if parent == absolute {
		name = "."
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return parentRootPath{}, fmt.Errorf("open parent directory: %w", err)
	}
	return parentRootPath{root: root, name: name}, nil
}

func (path *parentRootPath) close(resultErr *error) {
	if path == nil || path.root == nil {
		return
	}
	if err := path.root.Close(); err != nil {
		*resultErr = errors.Join(*resultErr, fmt.Errorf("close parent directory: %w", err))
	}
	path.root = nil
}

func readOperatorSelectedFile(path string) (data []byte, resultErr error) {
	rooted, err := openParentRootPath(path)
	if err != nil {
		return nil, err
	}
	defer rooted.close(&resultErr)

	data, err = rooted.root.ReadFile(rooted.name)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func lstatWithinParent(path string) (info os.FileInfo, resultErr error) {
	rooted, err := openParentRootPath(path)
	if err != nil {
		return nil, err
	}
	defer rooted.close(&resultErr)

	info, err = rooted.root.Lstat(rooted.name)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func statWithinParent(path string) (info os.FileInfo, resultErr error) {
	rooted, err := openParentRootPath(path)
	if err != nil {
		return nil, err
	}
	defer rooted.close(&resultErr)

	info, err = rooted.root.Stat(rooted.name)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func removeWithinParent(path string) (resultErr error) {
	rooted, err := openParentRootPath(path)
	if err != nil {
		return err
	}
	defer rooted.close(&resultErr)
	return rooted.root.Remove(rooted.name)
}

func renameWithinParent(source string, destination string) (resultErr error) {
	sourceAbsolute, err := filepath.Abs(source)
	if err != nil {
		return fmt.Errorf("resolve evidence source path: %w", err)
	}
	destinationAbsolute, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("resolve evidence destination path: %w", err)
	}
	sourceAbsolute = filepath.Clean(sourceAbsolute)
	destinationAbsolute = filepath.Clean(destinationAbsolute)
	if filepath.Dir(sourceAbsolute) != filepath.Dir(destinationAbsolute) {
		return errors.New("evidence replacement source and destination must share a parent directory")
	}

	root, err := os.OpenRoot(filepath.Dir(sourceAbsolute))
	if err != nil {
		return fmt.Errorf("open evidence replacement parent: %w", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close evidence replacement parent: %w", err))
		}
	}()
	return root.Rename(filepath.Base(sourceAbsolute), filepath.Base(destinationAbsolute))
}

func ensureEvidenceParentDirectory(path string) (resultErr error) {
	absolute, err := canonicalEvidenceDestinationForParentCreation(path)
	if err != nil {
		return fmt.Errorf("resolve evidence destination path: %w", err)
	}
	destinationParent := filepath.Dir(filepath.Clean(absolute))
	volume := filepath.VolumeName(destinationParent)
	rootPath := volume + string(os.PathSeparator)
	if volume == "" {
		rootPath = string(os.PathSeparator)
	}
	relative, err := filepath.Rel(rootPath, destinationParent)
	if err != nil {
		return fmt.Errorf("resolve evidence parent below filesystem root: %w", err)
	}
	if relative == ".." || filepath.IsAbs(relative) || filepathHasParentTraversal(relative) {
		return errors.New("evidence parent escapes the filesystem root")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open evidence filesystem root: %w", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close evidence parent root: %w", err))
		}
	}()
	if relative == "." {
		return nil
	}

	currentPath := rootPath
	for _, component := range splitRelativePath(relative) {
		childPath := filepath.Join(currentPath, component)
		next, err := openOrCreateEvidenceDirectory(root, component, childPath)
		if err != nil {
			return err
		}
		if closeErr := root.Close(); closeErr != nil {
			root = next
			return fmt.Errorf("close evidence ancestor %q: %w", currentPath, closeErr)
		}
		root = next
		currentPath = childPath
	}
	return nil
}

func filepathHasParentTraversal(path string) bool {
	for _, component := range splitRelativePath(path) {
		if component == ".." {
			return true
		}
	}
	return false
}

func splitRelativePath(path string) []string {
	if path == "" || path == "." {
		return nil
	}
	components := make([]string, 0)
	for _, component := range strings.Split(path, string(os.PathSeparator)) {
		if component != "" && component != "." {
			components = append(components, component)
		}
	}
	return components
}

func openOrCreateEvidenceDirectory(root *os.Root, name string, displayPath string) (*os.Root, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create private evidence directory %q: %w", displayPath, err)
		}
		info, err = root.Lstat(name)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect evidence parent component %q: %w", displayPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("evidence parent component %q is a symbolic link", displayPath)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("evidence parent component %q is not a directory", displayPath)
	}
	next, err := root.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open evidence parent component %q: %w", displayPath, err)
	}
	openedInfo, err := next.Stat(".")
	if err != nil {
		primary := fmt.Errorf("inspect opened evidence parent component %q: %w", displayPath, err)
		if closeErr := next.Close(); closeErr != nil {
			primary = errors.Join(primary, fmt.Errorf("close unverified evidence parent component: %w", closeErr))
		}
		return nil, primary
	}
	if !os.SameFile(info, openedInfo) {
		primary := fmt.Errorf("evidence parent component %q changed while being opened", displayPath)
		if closeErr := next.Close(); closeErr != nil {
			primary = errors.Join(primary, fmt.Errorf("close changed evidence parent component: %w", closeErr))
		}
		return nil, primary
	}
	return next, nil
}
