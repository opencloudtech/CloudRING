// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package etcdrecovery

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

func newWorkspace(root string) (string, error) {
	clean := filepath.Clean(root)
	if !filepath.IsAbs(clean) || clean != root || clean == string(filepath.Separator) {
		return "", errors.New("workspace root path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil || resolved != clean {
		return "", errors.New("workspace root contains a link")
	}
	info, err := os.Lstat(clean)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o002 != 0 {
		return "", errors.New("workspace root is invalid")
	}
	directory, err := os.MkdirTemp(clean, ".cloudring-etcd-recovery-")
	if err != nil {
		return "", errors.New("create recovery workspace")
	}
	// #nosec G302 -- this is an owner-only directory, not a regular file.
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return "", errors.New("protect recovery workspace")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		_ = os.RemoveAll(directory)
		return "", errors.New("recovery workspace is not empty")
	}
	return directory, nil
}

func validateWorkspaceTree(ctx context.Context, root string, maximumFiles int, maximumBytes int64) error {
	if ctx == nil {
		return errors.New("recovery workspace context is invalid")
	}
	files := 0
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil || entry == nil {
			return errors.New("inspect recovery workspace")
		}
		if path == root {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("recovery workspace contains a link")
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("recovery workspace contains an unsupported object")
		}
		if !workspaceRegularSafe(info) {
			return errors.New("recovery workspace file identity is invalid")
		}
		files++
		total += info.Size()
		if files > maximumFiles || info.Size() < 0 || total > maximumBytes {
			return errors.New("recovery workspace exceeds its bounds")
		}
		return nil
	})
	if err != nil || files == 0 {
		return errors.New("recovery workspace result is invalid")
	}
	return nil
}

func validateWorkspaceLayout(ctx context.Context, root, sourceMode string) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("recovery workspace context is invalid")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return errors.New("inspect recovery workspace layout")
	}
	expected := map[string]bool{"restored.etcd": true}
	if sourceMode == "s3" {
		expected["archive.db"] = false
	} else if sourceMode != "local-file" {
		return errors.New("recovery workspace source mode is invalid")
	}
	if len(entries) != len(expected) {
		return errors.New("recovery workspace layout is invalid")
	}
	for _, entry := range entries {
		directory, ok := expected[entry.Name()]
		if !ok || entry.IsDir() != directory {
			return errors.New("recovery workspace contains an unexpected entry")
		}
		if !directory {
			info, statErr := entry.Info()
			if statErr != nil || !workspaceRegularSafe(info) || info.Size() <= 0 || info.Size() > MaxArchiveBytes {
				return errors.New("recovery workspace archive identity is invalid")
			}
		}
	}
	return validateWorkspaceTree(ctx, filepath.Join(root, "restored.etcd"), MaxRestoredFiles, MaxRestoredBytes)
}

func cleanupWorkspace(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("cleanup workspace path is invalid")
	}
	if err := os.RemoveAll(path); err != nil {
		return errors.New("remove recovery workspace")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("recovery workspace still exists")
	}
	return nil
}

func cleanupWorkspaceContext(ctx context.Context, path string) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("cleanup workspace context is invalid")
	}
	result := make(chan error, 1)
	go func() {
		result <- cleanupWorkspace(path)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return errors.New("recovery workspace cleanup timed out")
	}
}

func cleanupWithinLimit(cleanup func(context.Context, string) error, path string) bool {
	if cleanup == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), MaximumCleanupTimeout)
	defer cancel()
	return cleanup(ctx, path) == nil
}
