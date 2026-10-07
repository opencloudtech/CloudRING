// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package privateartifact reads existing and writes new owner-only JSON
// artifacts through stable directory handles without following or replacing
// the final path.
package privateartifact

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func WriteNewJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.New("marshal private artifact")
	}
	data = append(data, '\n')
	return WriteNew(path, data)
}

func WriteNew(path string, data []byte) error {
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return errors.New("private artifact path is invalid")
	}
	directory := filepath.Dir(clean)
	name := filepath.Base(clean)
	pathInfo, err := os.Lstat(directory)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() || !privateDirectoryMode(pathInfo.Mode()) {
		return errors.New("private artifact directory is not a trusted directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return errors.New("open private artifact directory")
	}
	defer root.Close()
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(pathInfo, rootInfo) {
		return errors.New("private artifact directory changed while opening")
	}
	if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errors.New("private artifact destination already exists")
	}

	temporaryName, err := randomTemporaryName()
	if err != nil {
		return err
	}
	file, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create private artifact temporary file")
	}
	defer root.Remove(temporaryName)
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return errors.New("write private artifact")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("sync private artifact")
	}
	if err := file.Close(); err != nil {
		return errors.New("close private artifact")
	}
	if err := root.Link(temporaryName, name); err != nil {
		return errors.New("publish private artifact without overwrite")
	}
	if err := root.Remove(temporaryName); err != nil {
		_ = root.Remove(name)
		return errors.New("remove private artifact temporary link")
	}
	if err := syncDirectory(root); err != nil {
		_ = root.Remove(name)
		return errors.New("sync private artifact directory")
	}
	return nil
}

func randomTemporaryName() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", errors.New("generate private artifact temporary name")
	}
	return ".cloudring-private-artifact-" + hex.EncodeToString(random), nil
}
