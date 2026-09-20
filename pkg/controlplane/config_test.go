// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package controlplane

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	return Config{ // #nosec G101 -- This configuration fixture contains public file paths only; it includes no private key, database password, or operator token value.
		APIVersion: APIVersion, Kind: RuntimeKind, Profile: DevelopmentProfile,
		InstallationID: "test-installation", PublicOrigin: "https://provider.test:8443", ListenAddress: ":8443",
		TLSCertificateFile: filepath.Join(root, "tls", "cert.pem"), TLSPrivateKeyFile: filepath.Join(root, "tls", "key.pem"),
		DatabaseDSNFile: filepath.Join(root, "db", "dsn"), DevelopmentOperatorTokenFile: filepath.Join(root, "operator", "token"),
		MigrationOwnerRole: "cloudring_owner", ApplicationRole: "cloudring_app",
	}
}

func TestConfigurationRejectsProductionAndAmbiguousInputs(t *testing.T) {
	valid := testConfig(t)
	body, _ := json.Marshal(valid)
	if _, err := ReadConfig(strings.NewReader(string(body))); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"production":         func(config *Config) { config.Profile = "production" },
		"production kind":    func(config *Config) { config.Kind = "CloudRINGProductionRuntime" },
		"http":               func(config *Config) { config.PublicOrigin = "http://provider.test:8443" },
		"origin path":        func(config *Config) { config.PublicOrigin += "/" },
		"origin credentials": func(config *Config) { config.PublicOrigin = "https://user@provider.test:8443" },
		"origin query":       func(config *Config) { config.PublicOrigin += "?unexpected=value" },
		"listen hostname":    func(config *Config) { config.ListenAddress = "ambient-host:8443" },
		"listen port zero":   func(config *Config) { config.ListenAddress = ":0" },
		"relative path":      func(config *Config) { config.DatabaseDSNFile = "dsn" },
		"unnormalized path": func(config *Config) {
			config.DatabaseDSNFile += string(os.PathSeparator) + ".." + string(os.PathSeparator) + "secret"
		},
		"same role":    func(config *Config) { config.ApplicationRole = config.MigrationOwnerRole },
		"role SQL":     func(config *Config) { config.ApplicationRole = "role;select" },
		"install path": func(config *Config) { config.InstallationID = "../another" },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if config.Validate() == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	for _, input := range []string{
		strings.TrimSuffix(string(body), "}") + `,"profile":"production"}`,
		strings.TrimSuffix(string(body), "}") + `,"allowInsecureForTests":true}`,
		string(body) + `{}`,
		strings.Repeat(" ", maximumConfigBytes+1),
	} {
		if _, err := ReadConfig(strings.NewReader(input)); err == nil {
			t.Fatal("ambiguous or overlarge configuration accepted")
		}
	}
}

func TestSecretInputsAreBoundedRoleSpecificAndPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Kubernetes projected-secret permissions require POSIX filesystem semantics")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "projected-secret")
	write := func(body string, permissions os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), permissions); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, permissions); err != nil {
			t.Fatal(err)
		}
	}
	operatorKey := strings.Repeat("a", 64)
	write(operatorKey+"\n", 0640)
	if actual, err := ReadDevelopmentOperatorToken(path); err != nil || actual != operatorKey {
		t.Fatal("valid projected token rejected")
	}
	link := filepath.Join(directory, "secret-link")
	if err := os.Symlink(filepath.Base(path), link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDevelopmentOperatorToken(link); err != nil {
		t.Fatal("Kubernetes projected secret link rejected")
	}
	projected := filepath.Join(directory, "..projected")
	if err := os.Mkdir(projected, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projected, "operator"), []byte(operatorKey), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..projected", filepath.Join(directory, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..data/operator", filepath.Join(directory, "operator")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDevelopmentOperatorToken(filepath.Join(directory, "operator")); err != nil {
		t.Fatal("Kubernetes atomic projected secret rejected")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte(operatorKey), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "escaped")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDevelopmentOperatorToken(filepath.Join(directory, "escaped")); err == nil {
		t.Fatal("secret link escaped its configured volume directory")
	}
	for _, value := range []string{operatorKey + "\n\n", operatorKey + " ", strings.ToUpper(operatorKey), "", strings.Repeat("b", 300)} {
		write(value, 0600)
		if _, err := ReadDevelopmentOperatorToken(path); err == nil {
			t.Fatal("invalid token accepted")
		}
	}
	for _, mode := range []os.FileMode{0644, 0660, 0607} {
		write(operatorKey, mode)
		if _, err := ReadDevelopmentOperatorToken(path); err == nil {
			t.Fatal("exposed secret accepted")
		}
	}
	databaseURL := url.URL{Scheme: "postgresql", Host: "database.test:5432", Path: "/cloudring", User: url.UserPassword("cloudring_app", "isolated-generated-value")}
	query := url.Values{}
	query.Set("sslmode", "verify-full")
	query.Set("sslrootcert", filepath.Join(directory, "ca.pem"))
	databaseURL.RawQuery = query.Encode()
	dsn := databaseURL.String()
	write(dsn, 0600)
	if _, err := ReadDatabaseConfig(path, "cloudring_app"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDatabaseConfig(path, "cloudring_owner"); err == nil {
		t.Fatal("migration identity accepted for application")
	}
	query.Set("sslrootcert", "ambient-ca")
	databaseURL.RawQuery = query.Encode()
	for _, value := range []string{
		strings.Replace(dsn, "verify-full", "disable", 1),
		strings.Replace(dsn, ":isolated-generated-value", "", 1),
		databaseURL.String(),
	} {
		write(value, 0600)
		if _, err := ReadDatabaseConfig(path, "cloudring_app"); err == nil {
			t.Fatal("unsafe database binding accepted")
		}
	}
}

func TestMigrationConfigurationCannotCarryServingCredentials(t *testing.T) {
	config := MigrationConfig{APIVersion: APIVersion, Kind: MigrationKind, Profile: DevelopmentProfile,
		InstallationID: "test-installation", DatabaseDSNFile: filepath.Join(t.TempDir(), "dsn"), MigrationOwnerRole: "cloudring_owner", ApplicationRole: "cloudring_app"}
	body, _ := json.Marshal(config)
	if _, err := ReadMigrationConfig(strings.NewReader(string(body))); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(strings.NewReader(string(body))); err == nil {
		t.Fatal("migration configuration accepted as serving configuration")
	}
	withToken := strings.TrimSuffix(string(body), "}") + `,"developmentOperatorTokenFile":"/run/operator/token"}`
	if _, err := ReadMigrationConfig(strings.NewReader(withToken)); err == nil {
		t.Fatal("serving secret field accepted by migration")
	}
	config.Profile = "production"
	if config.Validate() == nil {
		t.Fatal("production profile accepted")
	}
}
