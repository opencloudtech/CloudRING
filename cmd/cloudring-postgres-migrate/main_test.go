// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

func TestRunReadsProtectedInputWithoutReturningIt(t *testing.T) {
	marker := "opaque-sensitive-fixture"
	reader, writer := newDSNPipe(t, marker)
	var observed transactionalstate.Config
	err := run([]string{"--dsn-fd", fmt.Sprint(reader.Fd())}, func(_ context.Context, config transactionalstate.Config) error {
		observed = config
		return errors.New(marker)
	})
	if observed.DSN != marker || observed.MigrationOwnerRole != "cloudring_owner" || observed.ApplicationRole != "cloudring_app" {
		t.Fatal("migration did not receive the protected input and separated roles")
	}
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("redacted migration error = %q", err)
	}
	_ = writer.Close()
}

func TestRunForwardsExplicitRoleNames(t *testing.T) {
	reader, writer := newDSNPipe(t, "synthetic-dsn")
	var observed transactionalstate.Config
	err := run([]string{
		"--dsn-fd", fmt.Sprint(reader.Fd()),
		"--owner-role", "site_owner",
		"--application-role", "site_app",
	}, func(_ context.Context, config transactionalstate.Config) error {
		observed = config
		return nil
	})
	if err != nil || observed.MigrationOwnerRole != "site_owner" || observed.ApplicationRole != "site_app" {
		t.Fatalf("explicit migration roles = %#v, %v", observed, err)
	}
	_ = writer.Close()
}

func TestRunRejectsUnsafeInputShapes(t *testing.T) {
	reader, writer := newDSNPipe(t, "first\nsecond")
	called := false
	err := run([]string{"--dsn-fd", fmt.Sprint(reader.Fd())}, func(context.Context, transactionalstate.Config) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatal("multi-line database configuration reached the migration")
	}
	if err := run(nil, func(context.Context, transactionalstate.Config) error { return nil }); err == nil {
		t.Fatal("missing protected input was accepted")
	}
	_ = writer.Close()
}

func TestReadDSNRejectsRegularFile(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "database-config")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := readDSNFromFD(int(file.Fd())); err == nil {
		t.Fatal("regular-file database configuration was accepted")
	}
}

func TestReadDSNRejectsOversizedPipe(t *testing.T) {
	reader, _ := newDSNPipe(t, strings.Repeat("x", maximumDSNBytes+1))
	if _, err := readDSNFromFD(int(reader.Fd())); err == nil {
		t.Fatal("oversized database configuration was accepted")
	}
}

func newDSNPipe(t *testing.T, value string) (*os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	go func() {
		_, _ = writer.WriteString(value)
		_ = writer.Close()
	}()
	return reader, writer
}
