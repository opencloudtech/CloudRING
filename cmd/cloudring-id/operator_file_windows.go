// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"errors"
	"os"
	"path/filepath"
)

func openProtectedOperatorFile(path string, _ bool) (*os.File, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errors.New("open operator input directory")
	}
	defer root.Close()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("operator input must be a regular non-symlink file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errors.New("open protected operator input")
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, errors.New("operator input changed while opening")
	}
	return file, nil
}
