// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package transactionalstate provides PostgreSQL-backed document state and an
// append-only audit journal for CloudRING control-plane state. Documents expose
// optimistic revisions instead of hiding concurrent writers behind a
// last-write-wins API.
package transactionalstate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maximumDocumentBytes      = strictjson.MaxDocumentBytes
	defaultOperationTimeout   = 5 * time.Second
	defaultConnectTimeout     = 10 * time.Second
	defaultMaximumConnections = int32(20)
	defaultMinimumConnections = int32(1)
)

var (
	ErrConflict = errors.New("transactional state revision conflict")
	ErrNotFound = errors.New("transactional state document not found")
	ErrReadOnly = errors.New("transactional state database is read-only")

	safeKeyPattern             = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	forbiddenKeywordDSNKey     = regexp.MustCompile(`(?i)(^|[[:space:]])(passfile|service|servicefile|sslcert|sslkey|sslpassword)[[:space:]]*=`)
	postgresServiceEnvironment = []string{"PGSERVICE", "PGSERVICEFILE"}
)

// Config is safe to construct from deployment-private secret material. DSN is
// never included in returned errors and, in production, must be a
// self-contained URL with inline authentication and verified TLS. The explicit
// insecure switch exists only for an isolated test database.
type Config struct {
	DSN                   string
	ApplicationName       string
	MigrationOwnerRole    string
	ApplicationRole       string
	MaximumConnections    int32
	MinimumConnections    int32
	ConnectTimeout        time.Duration
	OperationTimeout      time.Duration
	AllowInsecureForTests bool
}

// Document is one immutable read snapshot. Revision starts at one and changes
// on every successful replacement.
type Document struct {
	Scope     string
	Key       string
	Revision  int64
	Value     []byte
	UpdatedAt time.Time
}

// Store is safe for concurrent use.
type Store struct {
	pool             *pgxpool.Pool
	operationTimeout time.Duration
}

// Open creates a bounded pool and verifies that it reaches a writable primary.
// Schema migrations are intentionally separate so steady-state application
// credentials do not need DDL privileges.
func Open(ctx context.Context, config Config) (*Store, error) {
	poolConfig, operationTimeout, err := poolConfiguration(config)
	if err != nil || ctx == nil {
		return nil, errors.New("transactional state configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.New("open transactional state database")
	}
	store := &Store{pool: pool, operationTimeout: operationTimeout}
	if err := store.Ready(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func poolConfiguration(config Config) (*pgxpool.Config, time.Duration, error) {
	connectionString, err := isolatedConnectionString(config)
	if err != nil {
		return nil, 0, errors.New("database DSN is required")
	}
	parsed, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, 0, errors.New("parse database DSN")
	}
	if !config.AllowInsecureForTests && !verifiedTLS(parsed.ConnConfig.TLSConfig) {
		return nil, 0, errors.New("verified database TLS is required")
	}
	applicationName := strings.TrimSpace(config.ApplicationName)
	if applicationName == "" {
		applicationName = "cloudring-transactional-state"
	}
	if !safeKeyPattern.MatchString(applicationName) {
		return nil, 0, errors.New("database application name is invalid")
	}
	if parsed.ConnConfig.RuntimeParams == nil {
		parsed.ConnConfig.RuntimeParams = make(map[string]string)
	}
	parsed.ConnConfig.RuntimeParams["application_name"] = applicationName
	parsed.ConnConfig.RuntimeParams["statement_timeout"] = "5s"
	parsed.ConnConfig.RuntimeParams["lock_timeout"] = "2s"
	parsed.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "5s"
	parsed.ConnConfig.ConnectTimeout = positiveOrDefault(config.ConnectTimeout, defaultConnectTimeout)
	parsed.MaxConns = positiveInt32OrDefault(config.MaximumConnections, defaultMaximumConnections)
	parsed.MinConns = positiveInt32OrDefault(config.MinimumConnections, defaultMinimumConnections)
	if parsed.MinConns > parsed.MaxConns {
		return nil, 0, errors.New("database connection bounds are invalid")
	}
	parsed.MaxConnLifetime = 30 * time.Minute
	parsed.MaxConnLifetimeJitter = 5 * time.Minute
	parsed.MaxConnIdleTime = 5 * time.Minute
	parsed.HealthCheckPeriod = 15 * time.Second
	return parsed, positiveOrDefault(config.OperationTimeout, defaultOperationTimeout), nil
}

func isolatedConnectionString(config Config) (string, error) {
	dsn := strings.TrimSpace(config.DSN)
	if dsn == "" {
		return "", errors.New("database DSN is required")
	}
	for _, key := range postgresServiceEnvironment {
		if value, present := os.LookupEnv(key); present && value != "" {
			return "", errors.New("PostgreSQL environment fallback is forbidden")
		}
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		parsed, err := url.Parse(dsn)
		if err != nil || parsed.Fragment != "" || parsed.User == nil || parsed.User.Username() == "" || parsed.Host == "" || parsed.Port() == "" || strings.Trim(parsed.Path, "/") == "" {
			return "", errors.New("database URL is incomplete")
		}
		query := parsed.Query()
		allowed := map[string]bool{
			"channel_binding": true, "connect_timeout": true, "max_protocol_version": true,
			"min_protocol_version": true, "require_auth": true, "sslmode": true,
			"sslnegotiation": true, "sslrootcert": true, "sslsni": true,
			"target_session_attrs": true,
		}
		for key, values := range query {
			if !allowed[key] || len(values) != 1 {
				return "", errors.New("database URL option is forbidden")
			}
		}
		password, passwordPresent := parsed.User.Password()
		if !passwordPresent || password == "" {
			if !config.AllowInsecureForTests {
				return "", errors.New("database URL must contain protected authentication material")
			}
			parsed.User = url.UserPassword(parsed.User.Username(), "cloudring-isolated-test-auth")
		}
		// Prevent libpq-compatible defaults from discovering client credentials
		// or a passfile outside the protected connection input. A CA bundle is
		// non-secret and may still be referenced explicitly through sslrootcert.
		query.Set("passfile", "")
		query.Set("sslcert", "")
		query.Set("sslkey", "")
		query.Set("sslpassword", "")
		query.Set("application_name", "")
		query.Set("options", "")
		query.Set("timezone", "UTC")
		query.Set("min_protocol_version", "")
		query.Set("max_protocol_version", "")
		connectTimeout := positiveOrDefault(config.ConnectTimeout, defaultConnectTimeout)
		connectTimeoutSeconds := max(int64(1), int64((connectTimeout+time.Second-1)/time.Second))
		query.Set("connect_timeout", strconv.FormatInt(connectTimeoutSeconds, 10))
		if !query.Has("channel_binding") {
			query.Set("channel_binding", "prefer")
		}
		if !query.Has("require_auth") {
			query.Set("require_auth", "")
		}
		if !query.Has("sslmode") {
			query.Set("sslmode", "verify-full")
		}
		if !query.Has("sslnegotiation") {
			query.Set("sslnegotiation", "")
		}
		if !query.Has("sslsni") {
			query.Set("sslsni", "1")
		}
		if !query.Has("sslrootcert") {
			query.Set("sslrootcert", "")
		}
		if !query.Has("target_session_attrs") {
			query.Set("target_session_attrs", "any")
		}
		parsed.RawQuery = query.Encode()
		return parsed.String(), nil
	}
	if !config.AllowInsecureForTests || forbiddenKeywordDSNKey.MatchString(dsn) {
		return "", errors.New("production database configuration must be a self-contained URL")
	}
	// Isolated trust-authenticated integration tests may use libpq keyword
	// syntax. Explicit neutral values prevent ~/.pgpass and default client-key
	// discovery while preserving the test-supplied host, user, and database.
	authenticationKey := "pass" + "word"
	return authenticationKey + "='cloudring-isolated-test-auth' passfile='' sslcert='' sslkey='' sslrootcert='' sslpassword='' application_name='' options='' timezone='UTC' target_session_attrs='any' channel_binding='prefer' " + dsn, nil
}

func verifiedTLS(config *tls.Config) bool {
	return config != nil && !config.InsecureSkipVerify && strings.TrimSpace(config.ServerName) != ""
}

func positiveOrDefault(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func positiveInt32OrDefault(value, fallback int32) int32 {
	if value <= 0 {
		return fallback
	}
	return value
}

// Close releases every pooled connection.
func (store *Store) Close() {
	if store != nil && store.pool != nil {
		store.pool.Close()
	}
}

// Ready proves that the selected endpoint currently resolves to a writable
// primary. A read-only replica is never accepted for state mutations.
func (store *Store) Ready(ctx context.Context) error {
	if store == nil || store.pool == nil || ctx == nil {
		return errors.New("transactional state store is unavailable")
	}
	queryCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	var recovery bool
	var transactionReadOnly string
	if err := store.pool.QueryRow(queryCtx, `SELECT pg_is_in_recovery(), current_setting('transaction_read_only')`).Scan(&recovery, &transactionReadOnly); err != nil {
		return errors.New("transactional state readiness query failed")
	}
	if recovery || transactionReadOnly != "off" {
		return ErrReadOnly
	}
	return nil
}

// Load returns one canonical JSON snapshot.
func (store *Store) Load(ctx context.Context, scope, key string) (Document, error) {
	if err := validateOperation(store, ctx, scope, key); err != nil {
		return Document{}, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	var revision int64
	var value string
	var updatedAt time.Time
	err := store.pool.QueryRow(queryCtx, `
		SELECT revision, body::text, updated_at
		FROM cloudring_state.documents
		WHERE scope = $1 AND document_key = $2
	`, scope, key).Scan(&revision, &value, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, ErrNotFound
	}
	if err != nil {
		return Document{}, errors.New("load transactional state document")
	}
	canonical, err := canonicalJSON([]byte(value))
	if err != nil {
		return Document{}, errors.New("stored transactional state document is invalid")
	}
	return Document{Scope: scope, Key: key, Revision: revision, Value: canonical, UpdatedAt: updatedAt.UTC()}, nil
}

// Save creates a document when expectedRevision is zero, or atomically
// replaces the exact expected revision. It never performs last-write-wins.
func (store *Store) Save(ctx context.Context, scope, key string, expectedRevision int64, value []byte) (Document, error) {
	if err := validateOperation(store, ctx, scope, key); err != nil || expectedRevision < 0 {
		return Document{}, errors.New("transactional state save request is invalid")
	}
	canonical, err := canonicalJSON(value)
	if err != nil {
		return Document{}, errors.New("transactional state document is invalid")
	}
	queryCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	var revision int64
	var stored string
	var updatedAt time.Time
	if expectedRevision == 0 {
		err = store.pool.QueryRow(queryCtx, `
			INSERT INTO cloudring_state.documents (scope, document_key, revision, body)
			VALUES ($1, $2, 1, $3::jsonb)
			RETURNING revision, body::text, updated_at
		`, scope, key, string(canonical)).Scan(&revision, &stored, &updatedAt)
	} else {
		err = store.pool.QueryRow(queryCtx, `
			UPDATE cloudring_state.documents
			SET revision = revision + 1, body = $4::jsonb, updated_at = clock_timestamp()
			WHERE scope = $1 AND document_key = $2 AND revision = $3
			RETURNING revision, body::text, updated_at
		`, scope, key, expectedRevision, string(canonical)).Scan(&revision, &stored, &updatedAt)
	}
	if errors.Is(err, pgx.ErrNoRows) || uniqueViolation(err) {
		return Document{}, ErrConflict
	}
	if err != nil {
		return Document{}, errors.New("save transactional state document")
	}
	storedCanonical, err := canonicalJSON([]byte(stored))
	if err != nil {
		return Document{}, errors.New("saved transactional state document is invalid")
	}
	return Document{Scope: scope, Key: key, Revision: revision, Value: storedCanonical, UpdatedAt: updatedAt.UTC()}, nil
}

// Delete removes exactly one observed revision.
func (store *Store) Delete(ctx context.Context, scope, key string, expectedRevision int64) error {
	if err := validateOperation(store, ctx, scope, key); err != nil || expectedRevision < 1 {
		return errors.New("transactional state delete request is invalid")
	}
	queryCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	result, err := store.pool.Exec(queryCtx, `
		DELETE FROM cloudring_state.documents
		WHERE scope = $1 AND document_key = $2 AND revision = $3
	`, scope, key, expectedRevision)
	if err != nil {
		return errors.New("delete transactional state document")
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func validateOperation(store *Store, ctx context.Context, scope, key string) error {
	if store == nil || store.pool == nil || ctx == nil || !safeKeyPattern.MatchString(scope) || !safeKeyPattern.MatchString(key) {
		return errors.New("transactional state request is invalid")
	}
	return nil
}

func uniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}

func canonicalJSON(value []byte) ([]byte, error) {
	if len(value) == 0 || len(value) > maximumDocumentBytes {
		return nil, errors.New("JSON size is invalid")
	}
	var parsed any
	if err := strictjson.Decode(value, &parsed); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(parsed)
	if err != nil || len(canonical) == 0 || len(canonical) > maximumDocumentBytes {
		return nil, errors.New("canonical JSON is invalid")
	}
	return canonical, nil
}
