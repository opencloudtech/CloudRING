// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

const maximumDSNBytes = 16 << 10

type migrateFunc func(context.Context, transactionalstate.Config) error

func main() {
	if err := run(os.Args[1:], transactionalstate.Migrate); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "cloudring-postgres-migrate:", err)
		os.Exit(1)
	}
}

func run(args []string, migrate migrateFunc) error {
	flags := flag.NewFlagSet("cloudring-postgres-migrate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dsnFD := flags.Int("dsn-fd", -1, "inherited anonymous or named pipe containing the PostgreSQL DSN")
	applicationName := flags.String("application-name", "cloudring-postgres-migrate", "PostgreSQL application_name")
	ownerRole := flags.String("owner-role", "cloudring_owner", "database and schema owner used by the migration")
	applicationRole := flags.String("application-role", "cloudring_app", "least-privileged steady-state application role")
	timeout := flags.Duration("timeout", 2*time.Minute, "complete migration timeout")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *dsnFD < 3 || *timeout <= 0 || migrate == nil {
		return errors.New("invalid arguments")
	}
	dsn, err := readDSNFromFD(*dsnFD)
	if err != nil {
		return errors.New("cannot read protected database configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := migrate(ctx, transactionalstate.Config{
		DSN:                dsn,
		ApplicationName:    *applicationName,
		MigrationOwnerRole: *ownerRole,
		ApplicationRole:    *applicationRole,
		OperationTimeout:   *timeout,
	}); err != nil {
		return errors.New("transactional state migration failed")
	}
	return nil
}

func readDSNFromFD(fd int) (string, error) {
	file := os.NewFile(uintptr(fd), "cloudring-postgres-dsn-pipe-"+strconv.Itoa(fd))
	if file == nil {
		return "", errors.New("database configuration descriptor is invalid")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return "", errors.New("database configuration descriptor is not a pipe")
	}
	value, err := io.ReadAll(io.LimitReader(file, maximumDSNBytes+1))
	if err != nil || len(value) == 0 || len(value) > maximumDSNBytes {
		return "", errors.New("database configuration size is invalid")
	}
	dsn := strings.TrimSpace(string(value))
	if dsn == "" || strings.ContainsAny(dsn, "\r\n\x00") {
		return "", errors.New("database configuration format is invalid")
	}
	return dsn, nil
}
