// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

// This test creates a new random database and login inside the CI PostgreSQL
// service. It never drops or truncates an existing database, schema or role.
// The ordinary serving configuration has no AllowInsecureForTests path.
func TestPostgreSQLProviderRuntimeJourney(t *testing.T) {
	dsn := os.Getenv("CLOUDRING_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDRING_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("connect isolated PostgreSQL service")
	}
	defer admin.Close()
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal("create unique integration identity")
	}
	suffix := hex.EncodeToString(random)
	databaseName, applicationRole := "cloudring_c02_"+suffix, "cloudring_c02_app_"+suffix
	databasePassphrase := suffix + hex.EncodeToString(random)
	var ownerRole string
	if admin.QueryRow(ctx, "SELECT current_user").Scan(&ownerRole) != nil {
		t.Fatal("read integration owner")
	}
	applicationIdentifier, databaseIdentifier := pgx.Identifier{applicationRole}.Sanitize(), pgx.Identifier{databaseName}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE ROLE "+applicationIdentifier+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS PASSWORD '"+databasePassphrase+"'"); err != nil {
		t.Fatal("create unique application role")
	}
	var roleOID uint32
	if admin.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", applicationRole).Scan(&roleOID) != nil {
		t.Fatal("capture application role identity")
	}
	defer func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		var observed uint32
		if admin.QueryRow(cleanup, "SELECT oid FROM pg_roles WHERE rolname=$1", applicationRole).Scan(&observed) != nil || observed != roleOID {
			t.Error("owned role identity changed before cleanup")
			return
		}
		if _, err := admin.Exec(cleanup, "DROP ROLE "+applicationIdentifier); err != nil {
			t.Error("remove owned integration role")
		}
	}()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+databaseIdentifier); err != nil {
		t.Fatal("create unique integration database")
	}
	var databaseOID uint32
	if admin.QueryRow(ctx, "SELECT oid FROM pg_database WHERE datname=$1", databaseName).Scan(&databaseOID) != nil {
		t.Fatal("capture integration database identity")
	}
	defer func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		var observed uint32
		if admin.QueryRow(cleanup, "SELECT oid FROM pg_database WHERE datname=$1", databaseName).Scan(&observed) != nil || observed != databaseOID {
			t.Error("owned database identity changed before cleanup")
			return
		}
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+databaseIdentifier+" WITH (FORCE)"); err != nil {
			t.Error("remove owned integration database")
		}
	}()
	migrationConnection, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse isolated migration connection")
	}
	migrationDSN := isolatedTestDSN(migrationConnection, databaseName, ownerRole, migrationConnection.Password)
	guard, err := pgx.Connect(ctx, migrationDSN)
	if err != nil {
		t.Fatal("open owned integration database guard")
	}
	var connectedOID uint32
	guardErr := guard.QueryRow(ctx, "SELECT oid FROM pg_database WHERE datname=current_database()").Scan(&connectedOID)
	_ = guard.Close(ctx)
	if guardErr != nil || connectedOID != databaseOID {
		t.Fatal("migration target is not the newly created integration database")
	}
	migration := transactionalstate.Config{DSN: migrationDSN, MigrationOwnerRole: ownerRole, ApplicationRole: applicationRole, AllowInsecureForTests: true}
	if transactionalstate.Migrate(ctx, migration) != nil {
		t.Fatal("migrate real integration database")
	}
	if transactionalstate.Migrate(ctx, migration) != nil {
		t.Fatal("repeat real integration migration")
	}
	application := transactionalstate.Config{DSN: isolatedTestDSN(migrationConnection, databaseName, applicationRole, databasePassphrase), AllowInsecureForTests: true}
	store, err := transactionalstate.Open(ctx, application)
	if err != nil {
		t.Fatal("open real application connection")
	}
	defer store.Close()
	if store.VerifyApplicationIdentity(ctx, ownerRole, applicationRole) != nil {
		t.Fatal("least-privileged application identity was not verified")
	}
	runProviderJourney(t, store)
	runDelayedOldLogoutJourney(t, store)
	// A new pool models an actual database/client disconnect, in addition to
	// the handler recreation exercised by the common HTTP journey.
	first := newTestServer(t, store)
	login := perform(first, "POST", "/login", loginForm(first.operatorToken), "", nil)
	requireStatus(t, login, http.StatusSeeOther)
	cookie := login.Result().Cookies()[0]
	store.Close()
	requireStatus(t, perform(first, "GET", "/healthz/ready", "", "", nil), http.StatusServiceUnavailable)
	restartedStore, err := transactionalstate.Open(ctx, application)
	if err != nil {
		t.Fatal("reconnect durable application state")
	}
	defer restartedStore.Close()
	restarted := newTestServer(t, restartedStore)
	response := perform(restarted, "GET", "/", "", "", cookie)
	requireStatus(t, response, http.StatusOK)
	if !strings.Contains(response.Body.String(), "dev-operator:"+restarted.config.InstallationID) {
		t.Fatal("real PostgreSQL session did not survive reconnect")
	}
	foreign := restarted.config
	foreign.InstallationID = "other-installation"
	if _, err := New(ctx, foreign, restartedStore, restarted.operatorToken, BuildInfo{}); err == nil {
		t.Fatal("foreign installation adopted persisted state")
	}
	// Runtime checks effective privileges, not a role's reassuring name.
	if _, err := admin.Exec(ctx, "ALTER ROLE "+applicationIdentifier+" CREATEDB"); err != nil {
		t.Fatal("inject isolated privilege drift")
	}
	if restartedStore.VerifyApplicationIdentity(ctx, ownerRole, applicationRole) == nil {
		t.Fatal("elevated application privilege was accepted")
	}
	if _, err := admin.Exec(ctx, "ALTER ROLE "+applicationIdentifier+" NOCREATEDB"); err != nil {
		t.Fatal("remove isolated privilege drift")
	}
	if restartedStore.VerifyApplicationIdentity(ctx, ownerRole, applicationRole) != nil {
		t.Fatal("restored least-privileged identity was rejected")
	}
	t.Log("real PostgreSQL provider: migration/retry/API/denial/browser-session/restart/logout/concurrent-session-revocation/identity-binding/effective-privileges passed")
}

func isolatedTestDSN(parsed *pgx.ConnConfig, databaseName, role, password string) string {
	// pgx ConnString returns the original parsed string, not later Config
	// field mutations. Construct the isolated target explicitly and verify its
	// captured database OID above before invoking any schema mutation.
	values := url.Values{}
	values.Set("sslmode", "disable")
	connection := url.URL{Scheme: "postgresql", Host: net.JoinHostPort(parsed.Host, strconv.Itoa(int(parsed.Port))), Path: "/" + databaseName, User: url.UserPassword(role, password), RawQuery: values.Encode()}
	return connection.String()
}
