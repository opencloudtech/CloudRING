// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package kubeconfigpipe

import (
	"os/exec"
	"slices"
	"testing"
)

func TestExplicitEnvironmentNamesValidation(t *testing.T) {
	for _, names := range [][]string{nil, {}, {"PROVIDER_APPLICATION_KEY", "provider_consumer_key2"}} {
		if err := ValidateEnvironmentNames(names); err != nil {
			t.Fatalf("valid names rejected: %v", err)
		}
	}
	for _, names := range [][]string{{""}, {"NAME=value"}, {"NAME\n"}, {"9NAME"}, {"NAMÉ"}, {"NAME", "NAME"}, {"KUBECONFIG"}, {"GIT_TERMINAL_PROMPT"}, {"PATH"}, {"HOME"}, {"LANG"}, {"LC_ALL"}, {"LD_PRELOAD"}, {"DYLD_INSERT_LIBRARIES"}, {"BASH_ENV"}, {"ENV"}} {
		if ValidateEnvironmentNames(names) == nil {
			t.Fatal("unsafe names accepted")
		}
	}
}

func TestExplicitEnvironmentNamesDoNotInheritAmbientValues(t *testing.T) {
	if RunWithEnvironmentNames(nil, nil, nil) == nil {
		t.Fatal("nil command accepted")
	}
	if RunWithEnvironmentNames(&exec.Cmd{}, nil, []string{"PROVIDER_KEY"}) == nil {
		t.Fatal("implicit ambient environment accepted")
	}
	environment := []string{"LANG=C", "PROVIDER_KEY=synthetic-selected", "OTHER_KEY=synthetic-unselected", "KUBECONFIG=/tmp/unsafe"}
	clean := restrictedEnvironmentWithNames(environment, 4, []string{"PROVIDER_KEY"})
	if !slices.Equal(clean, []string{"LANG=C", "PROVIDER_KEY=synthetic-selected", "GIT_TERMINAL_PROMPT=0", "KUBECONFIG=/dev/fd/4"}) {
		t.Fatal("explicit filtering changed locale, selected values, or replay control")
	}
	if slices.Contains(restrictedEnvironment(environment, 4), "PROVIDER_KEY=synthetic-selected") {
		t.Fatal("default filtering inherited opt-in names")
	}
}
