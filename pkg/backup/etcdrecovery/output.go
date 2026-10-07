// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package etcdrecovery

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/opencloudtech/CloudRING/internal/privateartifact"
)

func WriteReceipt(path string, receipt Receipt) error {
	payload, err := CanonicalReceipt(receipt)
	if err != nil {
		return err
	}
	defer clear(payload)
	if len(payload) > maximumReceiptBytes {
		return errors.New("recovery receipt exceeds output bound")
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path || clean == string(filepath.Separator) {
		return errors.New("recovery receipt path is invalid")
	}
	directory := filepath.Dir(clean)
	parent := filepath.Dir(directory)
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o002 != 0 {
		return errors.New("recovery receipt parent is invalid")
	}
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("create recovery receipt directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByCurrentUser(info) {
		return errors.New("recovery receipt directory is invalid")
	}
	if err := privateartifact.WriteNew(clean, payload); err != nil {
		return errors.New("write recovery receipt")
	}
	return nil
}
