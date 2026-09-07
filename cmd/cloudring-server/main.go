// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/controlplane"
	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "cloudring-server:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 1 && args[0] == "version" {
		return json.NewEncoder(os.Stdout).Encode(buildInfo())
	}
	if len(args) < 1 || (args[0] != "serve" && args[0] != "migrate") {
		return errors.New("expected serve, migrate or version")
	}
	flags := flag.NewFlagSet("cloudring-server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "absolute path to the runtime or migration JSON configuration")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !filepath.IsAbs(*configPath) {
		return errors.New("invalid arguments")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return errors.New("cannot read control plane configuration")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("control plane configuration is not a regular file")
	}
	if args[0] == "migrate" {
		return migrate(ctx, file)
	}
	config, err := controlplane.ReadConfig(file)
	if err != nil {
		return err
	}
	return serve(ctx, config)
}

func migrate(ctx context.Context, reader io.Reader) error {
	config, err := controlplane.ReadMigrationConfig(reader)
	if err != nil {
		return err
	}
	database, err := controlplane.ReadDatabaseConfig(config.DatabaseDSNFile, config.MigrationOwnerRole)
	if err != nil {
		return err
	}
	database.MigrationOwnerRole, database.ApplicationRole = config.MigrationOwnerRole, config.ApplicationRole
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if transactionalstate.Migrate(bounded, database) != nil {
		return errors.New("control plane migration failed")
	}
	_, err = fmt.Fprintln(os.Stdout, "cloudring_control_plane_migration status=complete")
	return err
}

func serve(ctx context.Context, config controlplane.Config) error {
	database, err := controlplane.ReadDatabaseConfig(config.DatabaseDSNFile, config.ApplicationRole)
	if err != nil {
		return err
	}
	token, err := controlplane.ReadDevelopmentOperatorToken(config.DevelopmentOperatorTokenFile)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCertificateFile, config.TLSPrivateKeyFile)
	if err != nil {
		return errors.New("control plane TLS identity is invalid")
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	store, err := transactionalstate.Open(startup, database)
	if err != nil {
		cancel()
		return errors.New("control plane database is unavailable")
	}
	defer store.Close()
	if store.VerifyApplicationIdentity(startup, config.MigrationOwnerRole, config.ApplicationRole) != nil {
		cancel()
		return errors.New("control plane application role or schema is invalid")
	}
	handler, err := controlplane.New(startup, config, store, token, buildInfo())
	cancel()
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: config.ListenAddress, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}},
		// Never reflect HTTP requests, cookie material or TLS peer payloads in
		// process diagnostics. Status/diagnose obtains bounded public readback.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-finished:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("control plane listener failed")
		}
		return nil
	case <-ctx.Done():
		shutdown, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return errors.New("control plane shutdown timed out")
		}
		return nil
	}
}

func buildInfo() controlplane.BuildInfo {
	result := controlplane.BuildInfo{}
	if info, present := debug.ReadBuildInfo(); present {
		result.GoVersion = info.GoVersion
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				result.SourceRevision = setting.Value
			case "vcs.modified":
				result.SourceModified = setting.Value == "true"
			}
		}
	}
	return result
}
