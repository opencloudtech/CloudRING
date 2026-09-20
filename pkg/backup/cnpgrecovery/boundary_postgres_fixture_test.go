//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package cnpgrecovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type boundaryPostgreSQL struct {
	bin, root, sourceDirectory, restoreDirectory, archive string
	owner, password, sourceDSN, restoredDSN               string
	source                                                *pgx.Conn
	sourcePort                                            int
}

func newBoundaryPostgreSQL(t *testing.T, ctx context.Context, bin string) *boundaryPostgreSQL {
	t.Helper()
	if !filepath.IsAbs(bin) {
		t.Fatal("reviewed PostgreSQL binary directory must be absolute")
	}
	for _, name := range []string{"postgres", "pg_ctl", "initdb", "pg_basebackup"} {
		// #nosec G703 -- the opt-in test selects an absolute reviewed binary directory; name is from this fixed allowlist.
		info, err := os.Lstat(filepath.Join(bin, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
			t.Fatal("reviewed PostgreSQL binary is not a regular executable")
		}
	}
	// #nosec G204 G702 -- explicitly selected regular executable checked above; fixed argv, no shell evaluation.
	version, err := exec.CommandContext(ctx, filepath.Join(bin, "postgres"), "--version").Output()
	if err != nil || !strings.HasPrefix(string(version), "postgres (PostgreSQL) 18.") {
		t.Fatal("boundary integration requires reviewed PostgreSQL 18 binaries")
	}
	root := t.TempDir()
	// #nosec G302 -- this fresh private directory needs owner search permission.
	if os.Chmod(root, 0700) != nil {
		t.Fatal("protect owned boundary runtime directory")
	}
	fixture := &boundaryPostgreSQL{bin: bin, root: root, sourceDirectory: filepath.Join(root, "source"), restoreDirectory: filepath.Join(root, "restore"), archive: filepath.Join(root, "archive"), owner: "boundary_owner", sourcePort: boundaryPort(t)}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("generate ephemeral boundary credential")
	}
	fixture.password = hex.EncodeToString(random[:])
	clear(random[:])
	passwordPath := filepath.Join(root, "initdb-password")
	if os.WriteFile(passwordPath, []byte(fixture.password+"\n"), 0600) != nil || os.Mkdir(fixture.archive, 0700) != nil {
		t.Fatal("prepare private boundary runtime inputs")
	}
	fixture.run(t, ctx, "initdb", []string{"-D", fixture.sourceDirectory, "--username=" + fixture.owner, "--auth=scram-sha-256", "--pwfile=" + passwordPath, "--no-locale", "--encoding=UTF8"})
	if os.Remove(passwordPath) != nil {
		t.Fatal("remove consumed initdb credential file")
	}
	archiveScript := filepath.Join(root, "archive.sh")
	// These scripts operate only on generated test paths. No cloud archive,
	// caller-supplied shell or retained source backup is involved.
	// #nosec G306 -- this fixed test-only archive script must be executable by its owner inside the private t.TempDir.
	if os.WriteFile(archiveScript, []byte("#!/bin/sh\nset -eu\nif [ -f \"$2\" ]; then cmp \"$1\" \"$2\"; else cp \"$1\" \"$2\"; fi\n"), 0700) != nil {
		t.Fatal("create local test WAL archive command")
	}
	archiveCommand := boundaryShellQuote(archiveScript) + " '%p' " + boundaryShellQuote(filepath.Join(fixture.archive, "%f"))
	fixture.appendConfig(t, fixture.sourceDirectory, boundaryConfig(fixture.sourcePort)+"archive_mode='on'\narchive_command="+boundaryConfigQuote(archiveCommand)+"\n")
	fixture.sourceDSN = boundaryDSN(fixture.owner, fixture.password, fixture.sourcePort)
	fixture.source = fixture.start(t, ctx, fixture.sourceDirectory, fixture.sourceDSN, fixture.sourcePort)
	// #nosec G304 G703 -- fixed filename in the operator-selected absolute directory, verified regular/executable above.
	binary, err := os.ReadFile(filepath.Join(bin, "postgres"))
	if err != nil {
		t.Fatal("hash reviewed PostgreSQL test binary")
	}
	digest := sha256.Sum256(binary)
	t.Logf("owned PostgreSQL source verified: version=%s binarySHA256=%s port=%d; private data directory and postmaster PID captured", strings.TrimSpace(string(version)), hex.EncodeToString(digest[:]), fixture.sourcePort)
	return fixture
}

func (fixture *boundaryPostgreSQL) run(t *testing.T, ctx context.Context, name string, args []string) {
	t.Helper()
	// #nosec G204 G702 -- private fixture callers supply only the checked PostgreSQL tool names and argv; no caller-supplied shell is executed.
	command := exec.CommandContext(ctx, filepath.Join(fixture.bin, name), args...)
	// pg_basebackup forks its WAL receiver. Cancel the private process group
	// so that child cannot survive its parent and retain the output pipes.
	// pg_ctl's daemonized servers have their own captured-PID cleanup below.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 2 * time.Second
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "PG") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "PGPASSWORD="+fixture.password, "PGCONNECT_TIMEOUT=5", "PGPASSFILE="+filepath.Join(fixture.root, "absent-pgpass"))
	output, err := command.CombinedOutput()
	clear(output)
	if err != nil {
		t.Fatalf("owned PostgreSQL %s command failed", name)
	}
}

func (fixture *boundaryPostgreSQL) appendConfig(t *testing.T, directory, configuration string) {
	t.Helper()
	// #nosec G304 G703 -- both callers use only generated source/restore directories beneath this fixture's owner-only t.TempDir.
	file, err := os.OpenFile(filepath.Join(directory, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("open owned PostgreSQL configuration")
	}
	_, writeErr := file.WriteString(configuration)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("write owned PostgreSQL configuration")
	}
}

func (fixture *boundaryPostgreSQL) start(t *testing.T, ctx context.Context, directory, dsn string, port int) *pgx.Conn {
	t.Helper()
	if filepath.Dir(directory) != fixture.root || (directory != fixture.sourceDirectory && directory != fixture.restoreDirectory) {
		t.Fatal("PostgreSQL test data directory escaped ownership")
	}
	// #nosec G703 -- directory was checked against the two generated children of the private fixture root above.
	if _, err := os.Lstat(filepath.Join(directory, "postmaster.pid")); !os.IsNotExist(err) {
		t.Fatal("owned PostgreSQL start does not have an absent PID prestate")
	}
	pid := 0
	// Register before starting. An uncertain pg_ctl response can be reconciled
	// only inside this newly created owner-only directory and exact port; after
	// the PID is captured, replacement is rejected.
	t.Cleanup(func() {
		// #nosec G304 G703 -- exact fixed PID filename in the validated private data directory; contents are checked before any stop/removal.
		payload, err := os.ReadFile(filepath.Join(directory, "postmaster.pid"))
		if os.IsNotExist(err) && pid == 0 {
			return
		}
		observed := strings.Split(string(payload), "\n")
		if err != nil || len(observed) < 4 || observed[1] != directory || observed[3] != strconv.Itoa(port) {
			t.Error("owned PostgreSQL process changed before cleanup")
			return
		}
		observedPID, parseErr := strconv.Atoi(observed[0])
		if parseErr != nil || observedPID <= 1 || (pid != 0 && pid != observedPID) {
			t.Error("owned PostgreSQL PID changed before cleanup")
			return
		}
		pid = observedPID
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// #nosec G204 G702 -- checked pg_ctl executable and argv-only stop of the exact validated data directory/PID/port above.
		command := exec.CommandContext(cleanup, filepath.Join(fixture.bin, "pg_ctl"), "-D", directory, "-m", "fast", "-w", "-t", "25", "stop")
		output, err := command.CombinedOutput()
		clear(output)
		if err != nil {
			t.Error("stop exact owned PostgreSQL process")
			return
		}
		// #nosec G703 -- fixed filename in the same validated private directory after its captured postmaster was stopped.
		if _, err := os.Stat(filepath.Join(directory, "postmaster.pid")); !os.IsNotExist(err) {
			t.Error("owned postmaster PID file remains after stop")
			return
		}
		connection, err := net.DialTimeout("tcp", net.JoinHostPort(boundaryLoopbackHost(), strconv.Itoa(port)), 250*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			t.Error("owned PostgreSQL test listener remains after stop")
			return
		}
		// #nosec G703 -- exact generated private directory; captured PID, data path and port were rechecked, then stop and listener absence confirmed.
		if err := os.RemoveAll(directory); err != nil {
			t.Error("remove owned PostgreSQL test data")
			return
		}
		// #nosec G703 -- verify removal of that exact generated private directory.
		if _, err := os.Stat(directory); !os.IsNotExist(err) {
			t.Error("owned PostgreSQL test data remains after cleanup")
			return
		}
		t.Logf("owned PostgreSQL cleanup verified: pid=%d port=%d listener absent; exact data directory removed", pid, port)
	})
	fixture.run(t, ctx, "pg_ctl", []string{"-D", directory, "-l", filepath.Join(directory, "private-server.log"), "-w", "-t", "25", "start"})
	// #nosec G304 G703 -- fixed PID filename in the validated private source/restore directory; identity is verified immediately below.
	pidFile, err := os.ReadFile(filepath.Join(directory, "postmaster.pid"))
	lines := strings.Split(string(pidFile), "\n")
	if err != nil || len(lines) < 4 || lines[1] != directory || lines[3] != strconv.Itoa(port) {
		t.Fatal("started PostgreSQL process does not match owned data directory/port")
	}
	pid, err = strconv.Atoi(lines[0])
	if err != nil || pid <= 1 {
		t.Fatal("owned PostgreSQL postmaster identity is invalid")
	}
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("connect verified owned PostgreSQL process")
	}
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	var data, system string
	var observedPort int
	if connection.QueryRow(ctx, "SELECT current_setting('data_directory'),current_setting('port')::integer,(SELECT system_identifier::text FROM pg_control_system())").Scan(&data, &observedPort, &system) != nil || data != directory || observedPort != port || system == "" {
		t.Fatal("connected PostgreSQL server does not match owned runtime")
	}
	return connection
}

func (fixture *boundaryPostgreSQL) baseBackup(t *testing.T, ctx context.Context) {
	t.Helper()
	fixture.run(t, ctx, "pg_basebackup", []string{"--host=" + boundaryLoopbackHost(), "--port=" + strconv.Itoa(fixture.sourcePort), "--username=" + fixture.owner, "--no-password", "--pgdata=" + fixture.restoreDirectory, "--format=plain", "--wal-method=stream", "--checkpoint=fast"})
	// #nosec G703 -- fixed manifest filename in the generated restore directory beneath the owner-only fixture root.
	if info, err := os.Stat(filepath.Join(fixture.restoreDirectory, "backup_manifest")); err != nil || !info.Mode().IsRegular() {
		t.Fatal("owned physical base backup manifest is absent")
	}
}

func (fixture *boundaryPostgreSQL) restore(t *testing.T, ctx context.Context, marker string) *pgx.Conn {
	t.Helper()
	if !restoreMarkerNamePattern.MatchString(marker) {
		t.Fatal("physical recovery marker is invalid")
	}
	port := boundaryPort(t)
	if port == fixture.sourcePort {
		t.Fatal("physical recovery port collides with source")
	}
	restoreCommand := "cp " + boundaryShellQuote(filepath.Join(fixture.archive, "%f")) + " '%p'"
	configuration := boundaryConfig(port) + "archive_mode='off'\narchive_command=''\nprimary_conninfo=''\nrestore_command=" + boundaryConfigQuote(restoreCommand) + "\nrecovery_target_name=" + boundaryConfigQuote(marker) + "\nrecovery_target_action='promote'\nrecovery_target_timeline='current'\n"
	fixture.appendConfig(t, fixture.restoreDirectory, configuration)
	// #nosec G703 -- fixed recovery signal filename in the generated private restore directory; owner-only file mode.
	if os.WriteFile(filepath.Join(fixture.restoreDirectory, "recovery.signal"), nil, 0600) != nil {
		t.Fatal("create owned physical recovery signal")
	}
	fixture.restoredDSN = boundaryDSN(fixture.owner, fixture.password, port)
	return fixture.start(t, ctx, fixture.restoreDirectory, fixture.restoredDSN, port)
}
