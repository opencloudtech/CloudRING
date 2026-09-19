// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Package controlplane serves the public CloudRING management API and portal.
// Its first supported deployment is an explicitly isolated development provider.
package controlplane

import (
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

const (
	APIVersion         = "cloudring.org/v1alpha1"
	DevelopmentProfile = "development"
	RuntimeKind        = "CloudRINGDevelopmentRuntime"
	MigrationKind      = "CloudRINGDevelopmentMigration"
	maximumConfigBytes = 64 << 10
	maximumSecretBytes = 16 << 10
)

var (
	installationPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{2,62}$`)
	rolePattern          = regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`)
	operatorTokenPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	errConfiguration     = errors.New("control plane configuration is invalid")
)

// Config contains paths to projected secrets, never secret values. The serving
// process only receives the application DSN; migration is a separate command.
type Config struct {
	APIVersion                   string `json:"apiVersion"`
	Kind                         string `json:"kind"`
	Profile                      string `json:"profile"`
	InstallationID               string `json:"installationID"`
	PublicOrigin                 string `json:"publicOrigin"`
	ListenAddress                string `json:"listenAddress"`
	TLSCertificateFile           string `json:"tlsCertificateFile"`
	TLSPrivateKeyFile            string `json:"tlsPrivateKeyFile"`
	DatabaseDSNFile              string `json:"databaseDSNFile"`
	DevelopmentOperatorTokenFile string `json:"developmentOperatorTokenFile"`
	MigrationOwnerRole           string `json:"migrationOwnerRole"`
	ApplicationRole              string `json:"applicationRole"`
}

type MigrationConfig struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	Profile            string `json:"profile"`
	InstallationID     string `json:"installationID"`
	DatabaseDSNFile    string `json:"databaseDSNFile"`
	MigrationOwnerRole string `json:"migrationOwnerRole"`
	ApplicationRole    string `json:"applicationRole"`
}

func ReadConfig(reader io.Reader) (Config, error) {
	var config Config
	if err := readExact(reader, &config); err != nil || config.Validate() != nil {
		return Config{}, errConfiguration
	}
	return config, nil
}

func ReadMigrationConfig(reader io.Reader) (MigrationConfig, error) {
	var config MigrationConfig
	if err := readExact(reader, &config); err != nil || config.Validate() != nil {
		return MigrationConfig{}, errConfiguration
	}
	return config, nil
}

func readExact(reader io.Reader, target any) error {
	if reader == nil {
		return errConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(reader, maximumConfigBytes+1))
	if err != nil || len(data) > maximumConfigBytes || strictjson.DecodeExact(data, target) != nil {
		return errConfiguration
	}
	return nil
}

// Validate does not infer production safety from a single-node development
// binding. A production profile and all unrecognized fields fail closed.
func (config Config) Validate() error {
	if !validIdentity(config.APIVersion, config.Kind, RuntimeKind, config.Profile, config.InstallationID) ||
		!validRoles(config.MigrationOwnerRole, config.ApplicationRole) {
		return errConfiguration
	}
	origin, err := url.Parse(config.PublicOrigin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil ||
		origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.Opaque != "" ||
		strings.ContainsAny(origin.Host, "\r\n\\%") || origin.String() != config.PublicOrigin {
		return errConfiguration
	}
	if origin.Port() != "" && !validPort(origin.Port()) {
		return errConfiguration
	}
	host, port, err := net.SplitHostPort(config.ListenAddress)
	if err != nil || !validPort(port) || (host != "" && net.ParseIP(host) == nil) {
		return errConfiguration
	}
	for _, path := range []string{config.TLSCertificateFile, config.TLSPrivateKeyFile, config.DatabaseDSNFile, config.DevelopmentOperatorTokenFile} {
		if !validFilePath(path) {
			return errConfiguration
		}
	}
	return nil
}

func (config MigrationConfig) Validate() error {
	if !validIdentity(config.APIVersion, config.Kind, MigrationKind, config.Profile, config.InstallationID) ||
		!validRoles(config.MigrationOwnerRole, config.ApplicationRole) || !validFilePath(config.DatabaseDSNFile) {
		return errConfiguration
	}
	return nil
}

func validIdentity(version, kind, expectedKind, profile, installationID string) bool {
	return version == APIVersion && kind == expectedKind && profile == DevelopmentProfile && installationPattern.MatchString(installationID)
}

func validRoles(owner, application string) bool {
	return rolePattern.MatchString(owner) && rolePattern.MatchString(application) && owner != application
}

func validFilePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port > 0 && port <= 65535 && strconv.Itoa(port) == value
}

// ReadDatabaseConfig accepts only an explicit authenticated URL for the expected
// database role. There is no insecure TLS switch, passfile or environment DSN.
func ReadDatabaseConfig(path, expectedRole string) (transactionalstate.Config, error) {
	dsn, err := readSecretFile(path, maximumSecretBytes)
	if err != nil {
		return transactionalstate.Config{}, errConfiguration
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.User == nil ||
		parsed.User.Username() != expectedRole || !rolePattern.MatchString(expectedRole) ||
		parsed.Query().Get("sslmode") != "verify-full" || !validFilePath(parsed.Query().Get("sslrootcert")) {
		return transactionalstate.Config{}, errConfiguration
	}
	password, present := parsed.User.Password()
	if !present || password == "" {
		return transactionalstate.Config{}, errConfiguration
	}
	return transactionalstate.Config{DSN: dsn, ApplicationName: "cloudring-control-plane", MaximumConnections: 8, MinimumConnections: 1}, nil
}

func ReadDevelopmentOperatorToken(path string) (string, error) {
	token, err := readSecretFile(path, 65)
	if err != nil || !operatorTokenPattern.MatchString(token) {
		return "", errConfiguration
	}
	return token, nil
}

func readSecretFile(path string, maximum int64) (string, error) {
	if !validFilePath(path) {
		return "", errConfiguration
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return "", errConfiguration
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return "", errConfiguration
	}
	defer file.Close()
	info, err := file.Stat()
	// Kubernetes projected Secret files use relative symlinks within their
	// volume. Keep resolution inside that directory and validate the opened
	// target, allowing a read-only group but never world access or group writes.
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0027 != 0 || info.Size() > maximum {
		return "", errConfiguration
	}
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(value) > int(maximum) {
		return "", errConfiguration
	}
	text := strings.TrimSuffix(string(value), "\n")
	if text == "" || strings.ContainsAny(text, "\r\n\x00") || strings.TrimSpace(text) != text {
		return "", errConfiguration
	}
	return text, nil
}
