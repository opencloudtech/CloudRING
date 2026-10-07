// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package privateartifact

import (
	"errors"
	"os"
)

func privateDirectoryMode(os.FileMode) bool {
	return true
}

func syncDirectory(*os.Root) error {
	return nil
}

func readOwnerOnly(string, int64, func()) ([]byte, error) {
	return nil, errors.New("protected private artifact reads are unsupported on Windows")
}
