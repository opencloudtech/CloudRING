// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package privateartifact

import (
	"errors"
	"path/filepath"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

// ReadJSON reads one owner-only private artifact and decodes its exact JSON
// shape. Native Windows reads fail closed until an equivalent owner/DACL and
// stable-path implementation is available.
func ReadJSON(path string, destination any) error {
	absolute, err := cleanAbsoluteInput(path)
	if err != nil {
		return err
	}
	payload, err := readOwnerOnly(absolute, strictjson.MaxDocumentBytes, nil)
	if err != nil {
		return err
	}
	defer zeroBytes(payload)
	if err := strictjson.DecodeExact(payload, destination); err != nil {
		return errors.New("private artifact JSON is invalid")
	}
	return nil
}

func cleanAbsoluteInput(path string) (string, error) {
	if path == "" {
		return "", errors.New("private artifact input path is invalid")
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", errors.New("private artifact input path is invalid")
	}
	absolute = filepath.Clean(absolute)
	if !filepath.IsAbs(absolute) || absolute == string(filepath.Separator) {
		return "", errors.New("private artifact input path is invalid")
	}
	return absolute, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
