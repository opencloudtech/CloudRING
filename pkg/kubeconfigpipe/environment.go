// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package kubeconfigpipe

import (
	"errors"
	"strings"
)

// ValidateEnvironmentNames rejects malformed, duplicate, and execution-control
// names. This is an explicit trust decision about a reviewed executable, not a
// sandbox for arbitrary environment configuration.
func ValidateEnvironmentNames(names []string) error {
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if name == "" || seen[name] {
			return errors.New("invalid explicit environment names")
		}
		for index, character := range name {
			if character != '_' && !(character >= 'A' && character <= 'Z') && !(character >= 'a' && character <= 'z') && !(index > 0 && character >= '0' && character <= '9') {
				return errors.New("invalid explicit environment names")
			}
		}
		upper := strings.ToUpper(name)
		switch upper {
		case "PATH", "HOME", "LANG", "KUBECONFIG", "GIT_TERMINAL_PROMPT", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS":
			return errors.New("reserved explicit environment name")
		}
		if strings.HasPrefix(upper, "LC_") || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") {
			return errors.New("reserved explicit environment name")
		}
		seen[name] = true
	}
	return nil
}
