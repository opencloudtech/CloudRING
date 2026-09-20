// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package cnpgrecovery

import (
	"errors"
	"strings"
)

const boundarySourceSQL = `pg_catalog.json_build_object(
 'systemIdentifier', (SELECT system_identifier::text FROM pg_catalog.pg_control_system()),
 'timeline', (SELECT timeline_id FROM pg_catalog.pg_control_checkpoint()),
 'walSegmentBytes', pg_catalog.pg_size_bytes(pg_catalog.current_setting('wal_segment_size')),
 'serverStartedAt', pg_catalog.to_char(pg_catalog.pg_postmaster_start_time() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 'inRecovery', pg_catalog.pg_is_in_recovery())`

// SnapshotSQL is a single SELECT for an already-open repeatable-read read-only
// transaction. Collect the protected data and ownership catalog before ending
// that transaction. This observation never allocates an XID.
const SnapshotSQL = `SELECT pg_catalog.json_build_object(
 'source', ` + boundarySourceSQL + `,
 'snapshot', pg_catalog.pg_current_snapshot()::text,
 'isolation', pg_catalog.current_setting('transaction_isolation'),
 'readOnly', pg_catalog.current_setting('transaction_read_only') = 'on',
 'assignedXid', pg_catalog.pg_current_xact_id_if_assigned()::text)::text`

// MarkerSQL returns six ordered statements for one fresh connection-level
// transaction: BEGIN, the before observation, one named marker, the after
// observation, first XID allocation, COMMIT. The caller must execute them in
// order on one primary connection, collect all four SELECT results, and reject
// uncertain responses. On any error it must roll back/close the connection and
// reject this attempt. Do not merge these SELECTs or put the allocation in a
// CTE with the marker: expression evaluation order is not the required fence.
//
// Names must be unique per attempt, including after an uncertain response;
// PostgreSQL does not reject duplicate restore-point names. Archive the file
// returned for the marker LSN after pg_switch_wal(), not merely the later
// switch's file. This method does not switch WAL or claim archive completion.
// Restore-point LSNs address the end of a record, so subtract one byte when
// identifying its containing segment, including an exact segment boundary.
func MarkerSQL(name string) ([]string, error) {
	if !restoreMarkerNamePattern.MatchString(name) {
		return nil, errors.New("PostgreSQL restore marker name is invalid")
	}
	marker := strings.ReplaceAll(`WITH marker AS MATERIALIZED (
 SELECT pg_catalog.pg_create_restore_point('{{name}}') AS lsn)
 SELECT pg_catalog.json_build_object('name', '{{name}}', 'lsn', lsn::text,
 'walFile', pg_catalog.pg_walfile_name(lsn - 1))::text FROM marker`, "{{name}}", name)
	return []string{
		"BEGIN READ WRITE",
		`SELECT pg_catalog.json_build_object('source', ` + boundarySourceSQL + `, 'assignedXid', pg_catalog.pg_current_xact_id_if_assigned()::text)::text`,
		marker,
		`SELECT pg_catalog.json_build_object('source', ` + boundarySourceSQL + `, 'assignedXid', pg_catalog.pg_current_xact_id_if_assigned()::text)::text`,
		`SELECT pg_catalog.pg_current_xact_id()::text`,
		"COMMIT",
	}, nil
}
