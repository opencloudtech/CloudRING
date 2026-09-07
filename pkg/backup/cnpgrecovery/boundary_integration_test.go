//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package cnpgrecovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

// This opt-in test starts only two fresh, task-owned PostgreSQL clusters. It
// never connects to a caller-supplied database service or changes a system
// installation. CLOUDRING_POSTGRES_RECOVERY_BIN selects existing reviewed
// PostgreSQL 18 binaries; the companion fixture verifies both private servers
// and deletes their data after stopping their captured process identities.
func TestPostgreSQLSnapshotBoundaryAndPhysicalRecovery(t *testing.T) {
	bin := os.Getenv("CLOUDRING_POSTGRES_RECOVERY_BIN")
	if bin == "" {
		t.Skip("CLOUDRING_POSTGRES_RECOVERY_BIN is not set")
	}
	// Leave time for both owned servers to stop before Go's ordinary ten-minute
	// test deadline. A command timeout must not bypass their cleanup callbacks.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	fixture := newBoundaryPostgreSQL(t, ctx, bin)
	connection := fixture.source
	roles := transactionalstate.RecoveryRoles{Owner: fixture.owner, Application: "boundary_application"}
	identifier := pgx.Identifier{roles.Application}.Sanitize()
	if _, err := connection.Exec(ctx, "CREATE ROLE "+identifier+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS PASSWORD '"+fixture.password+"'"); err != nil {
		t.Fatal("create owned boundary application role")
	}
	if err := transactionalstate.Migrate(ctx, transactionalstate.Config{DSN: fixture.sourceDSN, MigrationOwnerRole: roles.Owner, ApplicationRole: roles.Application, AllowInsecureForTests: true}); err != nil {
		t.Fatal("migrate owned boundary database")
	}
	if _, err := connection.Exec(ctx, `INSERT INTO cloudring_state.documents(scope,document_key,body) VALUES ('boundary','baseline','{"value":1}'); INSERT INTO cloudring_state.audit_journal(scope,event_id,body,payload_sha256) VALUES ('boundary','baseline','{"value":1}',repeat('a',64))`); err != nil {
		t.Fatal("seed synthetic protected boundary state")
	}
	catalogSQL, err := transactionalstate.RecoveryContractSQL(roles)
	if err != nil {
		t.Fatal(err)
	}
	const logicalSQL = `SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.json_build_object(
 'documents',(SELECT pg_catalog.json_agg(row_to_json(d) ORDER BY scope COLLATE "C",document_key COLLATE "C") FROM cloudring_state.documents d),
 'audit',(SELECT pg_catalog.json_agg(row_to_json(a) ORDER BY scope COLLATE "C",event_id COLLATE "C") FROM cloudring_state.audit_journal a))::text,'UTF8')),'hex')`
	observe := func(t *testing.T) (BoundarySnapshot, string, string) {
		t.Helper()
		transaction, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal("begin boundary snapshot")
		}
		defer func() { _ = transaction.Rollback(context.Background()) }()
		var snapshotPayload, catalogPayload []byte
		var logical string
		if transaction.QueryRow(ctx, SnapshotSQL).Scan(&snapshotPayload) != nil || transaction.QueryRow(ctx, logicalSQL).Scan(&logical) != nil || transaction.QueryRow(ctx, catalogSQL).Scan(&catalogPayload) != nil {
			t.Fatal("capture all boundary observations in one read-only snapshot")
		}
		snapshot, err := DecodeBoundarySnapshot(snapshotPayload)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := transactionalstate.DecodeRecoveryContract(catalogPayload)
		if err != nil {
			t.Fatal(err)
		}
		catalogDigest, err := transactionalstate.RecoveryContractSHA256(catalog, roles)
		if err != nil {
			t.Fatal(err)
		}
		if transaction.Commit(ctx) != nil {
			t.Fatal("finish boundary snapshot")
		}
		return snapshot, logical, catalogDigest
	}
	marker := func(t *testing.T) BoundaryMarker {
		t.Helper()
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal("generate unique boundary marker")
		}
		statements, err := MarkerSQL("boundary_" + hex.EncodeToString(nonce[:]))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, statements[0]); err != nil {
			t.Fatal("begin fresh marker transaction")
		}
		defer func() { _, _ = connection.Exec(context.Background(), "ROLLBACK") }()
		rows := make([][]byte, 4)
		for i := range rows {
			if connection.QueryRow(ctx, statements[i+1]).Scan(&rows[i]) != nil {
				t.Fatal("execute ordered marker statement")
			}
		}
		if _, err := connection.Exec(ctx, statements[5]); err != nil {
			t.Fatal("complete marker transaction")
		}
		result, err := DecodeBoundaryMarker(rows)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	reject := func(t *testing.T, snapshot BoundarySnapshot) {
		t.Helper()
		if _, err := QualifyBoundary(snapshot, marker(t)); !errors.Is(err, ErrConsistentBoundaryUnavailable) {
			t.Fatalf("concurrent source interval was not rejected: %v", err)
		}
	}
	writer, err := pgx.Connect(ctx, fixture.sourceDSN)
	if err != nil {
		t.Fatal("connect owned boundary writer")
	}
	defer func() { _ = writer.Close(context.Background()) }()
	write := func(t *testing.T, query string) {
		t.Helper()
		if _, err := writer.Exec(ctx, query); err != nil {
			t.Fatal("perform allowed synthetic application write")
		}
	}
	t.Run("quiet-interval-qualifies", func(t *testing.T) {
		snapshot, _, _ := observe(t)
		if _, err := QualifyBoundary(snapshot, marker(t)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("committed-write-between-snapshot-and-marker", func(t *testing.T) {
		snapshot, _, _ := observe(t)
		write(t, `UPDATE cloudring_state.documents SET body='{"value":2}',revision=revision+1 WHERE scope='boundary'`)
		reject(t, snapshot)
	})
	t.Run("equal-empty-snapshots-with-newer-active-xid", func(t *testing.T) {
		before, beforeLogical, _ := observe(t)
		write(t, `BEGIN; UPDATE cloudring_state.documents SET body='{"value":3}',revision=revision+1 WHERE scope='boundary'`)
		defer write(t, "ROLLBACK")
		after, afterLogical, _ := observe(t)
		minimum, maximum, active, err := parseBoundarySnapshot(after.Snapshot)
		if err != nil || minimum != maximum || len(active) != 0 || before.Snapshot != after.Snapshot || beforeLogical != afterLogical {
			t.Fatal("did not reproduce equal empty snapshots with a newer active writer")
		}
		reject(t, after)
	})
	t.Run("older-active-writer", func(t *testing.T) {
		write(t, `BEGIN; UPDATE cloudring_state.documents SET body='{"value":4}',revision=revision+1 WHERE scope='boundary'`)
		defer write(t, "ROLLBACK")
		// Complete a later cluster-wide XID so the active writer precedes xmax.
		if _, err := connection.Exec(ctx, `SELECT pg_catalog.pg_current_xact_id()`); err != nil {
			t.Fatal("advance later owned transaction")
		}
		snapshot, _, _ := observe(t)
		minimum, maximum, active, err := parseBoundarySnapshot(snapshot.Snapshot)
		if err != nil || minimum == maximum || len(active) == 0 {
			t.Fatal("older active writer is not in the observed snapshot")
		}
		reject(t, snapshot)
	})
	t.Run("prepared-writer", func(t *testing.T) {
		write(t, `BEGIN; UPDATE cloudring_state.documents SET body='{"value":5}',revision=revision+1 WHERE scope='boundary'; PREPARE TRANSACTION 'boundary_owned_prepared'`)
		defer write(t, "ROLLBACK PREPARED 'boundary_owned_prepared'")
		snapshot, _, _ := observe(t)
		reject(t, snapshot)
	})
	t.Run("change-and-revert-does-not-fool-equal-hashes", func(t *testing.T) {
		snapshot, before, _ := observe(t)
		write(t, `UPDATE cloudring_state.documents SET body='{"value":6}' WHERE scope='boundary'`)
		write(t, `UPDATE cloudring_state.documents SET body='{"value":2}' WHERE scope='boundary'`)
		_, after, _ := observe(t)
		if before != after {
			t.Fatal("change/revert did not reproduce equal logical state")
		}
		reject(t, snapshot)
	})
	t.Run("writer-in-another-database", func(t *testing.T) {
		if _, err := connection.Exec(ctx, "CREATE DATABASE boundary_other"); err != nil {
			t.Fatal("create owned second database")
		}
		otherURL, _ := url.Parse(fixture.sourceDSN)
		otherURL.Path = "/boundary_other"
		other, err := pgx.Connect(ctx, otherURL.String())
		if err != nil {
			t.Fatal("connect owned second database")
		}
		defer func() { _ = other.Close(context.Background()) }()
		if _, err := other.Exec(ctx, "CREATE TABLE boundary_other(value integer)"); err != nil {
			t.Fatal("create owned second database fixture")
		}
		snapshot, _, _ := observe(t)
		if _, err := other.Exec(ctx, "BEGIN; INSERT INTO boundary_other VALUES (1)"); err != nil {
			t.Fatal("start synthetic writer in second database")
		}
		defer func() { _, _ = other.Exec(context.Background(), "ROLLBACK") }()
		reject(t, snapshot)
	})
	if t.Failed() {
		return
	}

	fixture.baseBackup(t, ctx)
	snapshot, logicalBefore, catalogBefore := observe(t)
	point := marker(t)
	qualified, err := QualifyBoundary(snapshot, point)
	if err != nil {
		t.Fatal(err)
	}
	boundaryDigest, err := BoundarySHA256(qualified)
	if err != nil {
		t.Fatal(err)
	}
	// This committed writer is deliberately after the accepted marker and must
	// remain absent from the physically recovered database.
	write(t, `INSERT INTO cloudring_state.documents(scope,document_key,body) VALUES ('boundary','after-marker','{"value":7}')`)
	if _, err := connection.Exec(ctx, "SELECT pg_catalog.pg_switch_wal()"); err != nil {
		t.Fatal("close marker WAL segment")
	}
	archiveDeadline := time.Now().Add(20 * time.Second)
	for {
		var archived bool
		if connection.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_ls_archive_statusdir() WHERE name=$1)", point.WALFile+".done").Scan(&archived) != nil {
			t.Fatal("observe exact marker WAL archive status")
		}
		if archived {
			break
		}
		if time.Now().After(archiveDeadline) {
			t.Fatal("exact marker segment was not archived")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if info, err := os.Stat(filepath.Join(fixture.archive, point.WALFile)); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatal("independent marker archive file is absent")
	}
	restored := fixture.restore(t, ctx, point.Name)
	var recovery bool
	var replayLSN, logicalAfter string
	var catalogPayload []byte
	// pg_ctl readiness includes read-only standby connections. Wait for the
	// configured target promotion before accepting the final replay position.
	promotion, promotionCancel := context.WithTimeout(ctx, 30*time.Second)
	defer promotionCancel()
	for {
		if restored.QueryRow(promotion, "SELECT pg_catalog.pg_is_in_recovery(),pg_catalog.pg_last_wal_replay_lsn()::text").Scan(&recovery, &replayLSN) != nil {
			t.Fatal("observe owned physical recovery promotion")
		}
		if !recovery {
			break
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-promotion.Done():
			timer.Stop()
			t.Fatal("owned physical recovery did not promote at its configured target")
		case <-timer.C:
		}
	}
	if replayLSN != point.LSN {
		t.Fatal("physical recovery replay position differs from the exact marker LSN")
	}
	if restored.QueryRow(ctx, logicalSQL).Scan(&logicalAfter) != nil || logicalAfter != logicalBefore {
		t.Fatal("physical marker recovery does not match all protected logical rows")
	}
	if restored.QueryRow(ctx, catalogSQL).Scan(&catalogPayload) != nil {
		t.Fatal("observe physically restored ownership and privileges")
	}
	catalog, err := transactionalstate.DecodeRecoveryContract(catalogPayload)
	if err != nil {
		t.Fatal(err)
	}
	catalogAfter, err := transactionalstate.RecoveryContractSHA256(catalog, roles)
	if err != nil || catalogAfter != catalogBefore {
		t.Fatal("physically restored ownership and privileges differ")
	}
	var rows int
	if restored.QueryRow(ctx, "SELECT count(*) FROM cloudring_state.documents WHERE document_key='after-marker'").Scan(&rows) != nil || rows != 0 {
		t.Fatal("writer after the marker contaminated physical recovery")
	}
	appURL, _ := url.Parse(fixture.restoredDSN)
	appURL.User = url.UserPassword(roles.Application, fixture.password)
	app, err := pgx.Connect(ctx, appURL.String())
	if err != nil {
		t.Fatal("authenticate the physically restored application role")
	}
	defer func() { _ = app.Close(context.Background()) }()
	var user string
	if app.QueryRow(ctx, "SELECT current_user").Scan(&user) != nil || user != roles.Application {
		t.Fatal("physical recovery application login used a different role")
	}
	if app.QueryRow(ctx, "SELECT count(*) FROM cloudring_state.documents").Scan(&rows) != nil || rows != 1 {
		t.Fatal("restored application could not read retained state")
	}
	t.Logf("qualified boundary=%s exact replay LSN verified; logical=%s ownership=%s; post-marker row absent; restored SCRAM application login passed", boundaryDigest, logicalAfter, catalogAfter)
}

func boundaryLoopbackHost() string { return net.IPv4(127, 0, 0, 1).String() }

func boundaryPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(boundaryLoopbackHost(), "0"))
	if err != nil {
		t.Fatal("reserve private boundary test port")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if listener.Close() != nil {
		t.Fatal("release private boundary test port reservation")
	}
	return port
}

func boundaryDSN(owner, password string, port int) string {
	u := url.URL{Scheme: "postgres", User: url.UserPassword(owner, password), Host: net.JoinHostPort(boundaryLoopbackHost(), strconv.Itoa(port)), Path: "/postgres"}
	query := url.Values{}
	query.Set("sslmode", "disable")
	query.Set("connect_timeout", "5")
	u.RawQuery = query.Encode()
	return u.String()
}

func boundaryShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
func boundaryConfigQuote(value string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "'", "''") + "'"
}

func boundaryConfig(port int) string {
	return fmt.Sprintf("\nlisten_addresses='%s'\nport=%d\nunix_socket_directories=''\nshared_buffers='32MB'\nmax_prepared_transactions=10\nmax_wal_senders=5\nwal_level=replica\n", boundaryLoopbackHost(), port)
}

func TestPostgreSQLMarkerAtWALSegmentBoundary(t *testing.T) {
	bin := os.Getenv("CLOUDRING_POSTGRES_RECOVERY_BIN")
	if bin == "" {
		t.Skip("PostgreSQL recovery binary directory is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fixture := newBoundaryPostgreSQL(t, ctx, bin)
	var current string
	var segment uint64
	if fixture.source.QueryRow(ctx, `SELECT pg_current_wal_insert_lsn()::text,pg_size_bytes(current_setting('wal_segment_size'))`).Scan(&current, &segment) != nil {
		t.Fatal("read private WAL position")
	}
	lsnNumber := func(value string) uint64 {
		pieces := strings.Split(value, "/")
		high, _ := strconv.ParseUint(pieces[0], 16, 32)
		low, _ := strconv.ParseUint(pieces[1], 16, 32)
		return high<<32 | low
	}
	usable := func(value uint64) uint64 {
		full := value / segment
		offset := value % segment
		pages := offset / 8192
		bytes := offset % 8192
		if pages == 0 {
			if bytes == 0 {
				return full * (segment - 40 - (segment/8192-1)*24)
			}
			return full*(segment-40-(segment/8192-1)*24) + bytes - 40
		}
		result := full*(segment-40-(segment/8192-1)*24) + (8192 - 40) + (pages-1)*(8192-24)
		if bytes > 0 {
			result += bytes - 24
		}
		return result
	}
	end := (lsnNumber(current)/segment + 1) * segment
	start := end - 104 // MAXALIGN(24-byte WAL header + 2-byte short data header + 72-byte restore-point struct).
	available := usable(start) - usable(lsnNumber(current))
	if available < 55 || available > 1<<30 {
		t.Fatal("private WAL padding is outside one supported segment")
		return
	}
	padding := int64(available) - 55 // WAL/data headers, logical-message struct and two-byte prefix.
	var padded string
	if fixture.source.QueryRow(ctx, `SELECT pg_logical_emit_message(false,'r',repeat('x',$1::int))::text`, padding).Scan(&padded) != nil {
		t.Fatal("position next marker in private WAL")
	}
	if lsnNumber(padded) != start {
		t.Fatalf("PostgreSQL 18 WAL alignment assumption failed: actual=%s expected=%X/%X", padded, start>>32, start&0xffffffff)
	}
	transaction, err := fixture.source.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("begin private snapshot")
	}
	var payload []byte
	if transaction.QueryRow(ctx, SnapshotSQL).Scan(&payload) != nil || transaction.Commit(ctx) != nil {
		t.Fatal("capture private snapshot")
	}
	snapshot, err := DecodeBoundarySnapshot(payload)
	if err != nil {
		t.Fatal(err)
	}
	statements, err := MarkerSQL("exact_wal_boundary")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.source.Exec(ctx, statements[0]); err != nil {
		t.Fatal("begin private marker")
	}
	rows := make([][]byte, 4)
	for i := range rows {
		if fixture.source.QueryRow(ctx, statements[i+1]).Scan(&rows[i]) != nil {
			t.Fatal("execute private marker")
		}
	}
	if _, err = fixture.source.Exec(ctx, statements[5]); err != nil {
		t.Fatal("complete private marker")
	}
	marker, err := DecodeBoundaryMarker(rows)
	if err != nil {
		t.Fatal(err)
	}
	if lsnNumber(marker.LSN) != end {
		t.Fatalf("restore-point did not end exactly at boundary: %s", marker.LSN)
	}
	_, qualifyErr := QualifyBoundary(snapshot, marker)
	if qualifyErr != nil {
		t.Fatal("exact-boundary marker was not qualified")
	}
	var containing string
	if fixture.source.QueryRow(ctx, `SELECT pg_walfile_name($1::pg_lsn-1)`, marker.LSN).Scan(&containing) != nil {
		t.Fatal("observe segment holding marker end record")
	}
	if _, err = fixture.source.Exec(ctx, `SELECT pg_switch_wal()`); err != nil {
		t.Fatal("archive closed private WAL")
	}
	deadline := time.Now().Add(5 * time.Second)
	var actualArchived, reportedArchived bool
	for time.Now().Before(deadline) {
		if fixture.source.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_ls_archive_statusdir() WHERE name=$1),EXISTS(SELECT 1 FROM pg_ls_archive_statusdir() WHERE name=$2)`, containing+".done", marker.WALFile+".done").Scan(&actualArchived, &reportedArchived) != nil {
			t.Fatal("observe private archived marker")
		}
		if actualArchived {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("actual restore-point LSN=%s sourceQualificationAccepted=%t reportedWAL=%s actualContainingWAL=%s actualArchived=%t reportedArchived=%t", marker.LSN, qualifyErr == nil, marker.WALFile, containing, actualArchived, reportedArchived)
	if !actualArchived || !reportedArchived {
		t.Fatal("exact marker segment did not archive")
	}
	if marker.WALFile != containing {
		t.Fatal("marker SQL selected the following segment, not the segment containing the restore-point record")
	}
}
