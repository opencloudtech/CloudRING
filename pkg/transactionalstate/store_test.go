// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package transactionalstate

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
)

func TestCanonicalJSONPreservesNumbersAndSortsObjects(t *testing.T) {
	got, err := canonicalJSON([]byte(` {"z":9007199254740993,"a":[true,null]} `))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"a":[true,null],"z":9007199254740993}`)
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical JSON = %s, want %s", got, want)
	}
}

func TestCanonicalJSONRejectsUnsafeDocuments(t *testing.T) {
	for _, value := range [][]byte{nil, []byte(`{"ok":true} {"extra":true}`), []byte(`{"duplicate":1,"duplicate":2}`), bytes.Repeat([]byte(" "), maximumDocumentBytes+1)} {
		if _, err := canonicalJSON(value); err == nil {
			t.Fatalf("canonicalJSON accepted invalid input of length %d", len(value))
		}
	}
}

func TestPoolConfigurationFailsClosedOnUnverifiedTLS(t *testing.T) {
	disabledTLS := syntheticDatabaseURL(t, true, "disable")
	_, _, err := poolConfiguration(Config{DSN: disabledTLS})
	if err == nil {
		t.Fatal("unverified PostgreSQL transport was accepted")
	}
	config, timeout, err := poolConfiguration(Config{
		DSN:                   disabledTLS,
		AllowInsecureForTests: true,
	})
	if err != nil || config == nil || timeout <= 0 {
		t.Fatalf("isolated test configuration = %#v, %v", config, err)
	}
	verified, _, err := poolConfiguration(Config{DSN: syntheticDatabaseURL(t, true, "verify-full")})
	if err != nil || verified.ConnConfig.TLSConfig == nil || verified.ConnConfig.TLSConfig.ServerName != "database.example" {
		t.Fatalf("system-root verified TLS configuration = %#v, %v", verified, err)
	}
}

func TestPoolConfigurationRejectsExternalAuthenticationFallbacks(t *testing.T) {
	verified := syntheticDatabaseURL(t, true, "verify-full")
	parsedURL, err := url.Parse(verified)
	if err != nil {
		t.Fatal("parse synthetic database URL")
	}
	expectedAuthentication, _ := parsedURL.User.Password()
	t.Run("environment password ignored", func(t *testing.T) {
		t.Setenv("PGPASS"+"WORD", "external-auth-fixture")
		config, _, err := poolConfiguration(Config{DSN: verified})
		if err != nil || config.ConnConfig.Password != expectedAuthentication {
			t.Fatal("environment authentication changed the protected URL")
		}
	})
	t.Run("environment passfile ignored", func(t *testing.T) {
		t.Setenv("PGPASS"+"FILE", t.TempDir()+"/external")
		config, _, err := poolConfiguration(Config{DSN: verified})
		if err != nil || config.ConnConfig.Password != expectedAuthentication {
			t.Fatal("environment passfile changed the protected URL")
		}
	})
	t.Run("environment service rejected", func(t *testing.T) {
		t.Setenv("PGSERVICE", "external")
		if _, _, err := poolConfiguration(Config{DSN: verified}); err == nil {
			t.Fatal("environment service indirection was accepted")
		}
	})
	if _, _, err := poolConfiguration(Config{DSN: syntheticDatabaseURL(t, false, "verify-full")}); err == nil {
		t.Fatal("production database URL without inline authentication was accepted")
	}
	if _, _, err := poolConfiguration(Config{
		DSN:                   "host=database.example user=test dbname=test passfile=/tmp/external sslmode=disable",
		AllowInsecureForTests: true,
	}); err == nil {
		t.Fatal("passfile indirection was accepted for an isolated test")
	}
	serviceURL, err := url.Parse(verified)
	if err != nil {
		t.Fatal("parse synthetic database URL")
	}
	query := serviceURL.Query()
	query.Set("service", "external")
	serviceURL.RawQuery = query.Encode()
	if _, _, err := poolConfiguration(Config{DSN: serviceURL.String()}); err == nil {
		t.Fatal("service-file indirection was accepted")
	}
}

func TestSafeKeysRejectDeploymentData(t *testing.T) {
	for _, value := range []string{"", "Uppercase", "contains space", "../../escape", "https://endpoint.example"} {
		if safeKeyPattern.MatchString(value) {
			t.Fatalf("safe key accepted %q", value)
		}
	}
}

func TestMigrationChecksumIsStableAndNonEmpty(t *testing.T) {
	checksum := migrationOneChecksum()
	if len(checksum) != 64 || checksum != migrationOneChecksum() {
		t.Fatalf("migration checksum is not stable: %q", checksum)
	}
}

func TestMigrationRolesAreSeparatedAndSafe(t *testing.T) {
	owner, application, err := migrationRoles(Config{})
	if err != nil || owner != "cloudring_owner" || application != "cloudring_app" {
		t.Fatalf("default migration roles = %q, %q, %v", owner, application, err)
	}
	for _, config := range []Config{
		{MigrationOwnerRole: "same_role", ApplicationRole: "same_role"},
		{MigrationOwnerRole: "Owner", ApplicationRole: "cloudring_app"},
		{MigrationOwnerRole: "cloudring_owner", ApplicationRole: "invalid-role"},
	} {
		if _, _, err := migrationRoles(config); err == nil {
			t.Fatalf("unsafe migration roles were accepted: %#v", config)
		}
	}
	statements := strings.Join(renderedMigrationOne(owner, application), "\n")
	if strings.Contains(statements, "{{") || !strings.Contains(statements, `"cloudring_owner"`) || !strings.Contains(statements, `"cloudring_app"`) {
		t.Fatal("migration SQL did not safely render separated roles")
	}
}

func syntheticDatabaseURL(t *testing.T, includeAuthentication bool, sslMode string) string {
	t.Helper()
	user := url.User("user")
	if includeAuthentication {
		user = url.UserPassword("user", "synthetic-auth-fixture")
	}
	value := &url.URL{
		Scheme: "postgres",
		User:   user,
		Host:   "database.example:5432",
		Path:   "/database",
	}
	query := value.Query()
	query.Set("sslmode", sslMode)
	value.RawQuery = query.Encode()
	return value.String()
}
