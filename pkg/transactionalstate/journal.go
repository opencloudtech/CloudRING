// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package transactionalstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	// MaximumAuditEventBytes is the maximum canonical JSON payload accepted by
	// AppendAuditEvent.
	MaximumAuditEventBytes = 256 * 1024
	// MaximumAuditPageSize bounds every audit-journal read.
	MaximumAuditPageSize = 100
)

// AuditEvent is one immutable journal entry. ID is supplied by the caller and
// must remain stable across retries. Scope is the tenant or other isolation
// boundary chosen by the caller.
type AuditEvent struct {
	Scope     string
	ID        string
	Value     []byte
	CreatedAt time.Time
}

// AuditEventPage is one deterministic ascending page. When NextAfterID is not
// empty, pass it as afterID to retrieve the next page.
type AuditEventPage struct {
	Events      []AuditEvent
	NextAfterID string
}

// AppendAuditEvent atomically appends an immutable event. Repeating an append
// with the same scope, ID, and canonical JSON is idempotent and returns the
// original event. Reusing an ID with different content returns ErrConflict.
func (store *Store) AppendAuditEvent(ctx context.Context, scope, eventID string, value []byte) (AuditEvent, error) {
	if err := validateOperation(store, ctx, scope, eventID); err != nil {
		return AuditEvent{}, errors.New("transactional state audit append request is invalid")
	}
	canonical, err := canonicalAuditJSON(value)
	if err != nil {
		return AuditEvent{}, errors.New("transactional state audit event is invalid")
	}
	queryCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	tx, err := store.pool.BeginTx(queryCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return AuditEvent{}, errors.New("begin transactional state audit append")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	payloadSHA256 := auditPayloadSHA256(canonical)
	record, inserted, err := insertAuditEvent(queryCtx, tx, scope, eventID, canonical, payloadSHA256)
	if err != nil {
		return AuditEvent{}, err
	}
	if !inserted {
		record, err = readAuditEventRecord(queryCtx, tx, scope, eventID)
		if err != nil {
			return AuditEvent{}, err
		}
		if record.PayloadSHA256 != payloadSHA256 {
			return AuditEvent{}, ErrConflict
		}
	}
	if err := tx.Commit(queryCtx); err != nil {
		return AuditEvent{}, errors.New("commit transactional state audit append")
	}
	return record.Event, nil
}

type auditEventRecord struct {
	Event         AuditEvent
	PayloadSHA256 string
}

func insertAuditEvent(ctx context.Context, tx pgx.Tx, scope, eventID string, canonical []byte, payloadSHA256 string) (auditEventRecord, bool, error) {
	var stored, storedSHA256 string
	var createdAt time.Time
	err := tx.QueryRow(ctx, `
		INSERT INTO cloudring_state.audit_journal (scope, event_id, body, payload_sha256)
		VALUES ($1, $2, $3::jsonb, $4)
		ON CONFLICT (scope, event_id) DO NOTHING
		RETURNING body::text, payload_sha256, created_at
	`, scope, eventID, string(canonical), payloadSHA256).Scan(&stored, &storedSHA256, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return auditEventRecord{}, false, nil
	}
	if err != nil {
		return auditEventRecord{}, false, errors.New("append transactional state audit event")
	}
	event, err := scannedAuditEvent(scope, eventID, stored, createdAt)
	if err != nil {
		return auditEventRecord{}, false, err
	}
	return auditEventRecord{Event: event, PayloadSHA256: storedSHA256}, true, nil
}

// ReadAuditEvent reads exactly one event within the supplied isolation scope.
func (store *Store) ReadAuditEvent(ctx context.Context, scope, eventID string) (AuditEvent, error) {
	if err := validateOperation(store, ctx, scope, eventID); err != nil {
		return AuditEvent{}, errors.New("transactional state audit read request is invalid")
	}
	queryCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	record, err := readAuditEventRecord(queryCtx, store.pool, scope, eventID)
	return record.Event, err
}

type auditEventQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readAuditEventRecord(ctx context.Context, querier auditEventQuerier, scope, eventID string) (auditEventRecord, error) {
	var stored, payloadSHA256 string
	var createdAt time.Time
	err := querier.QueryRow(ctx, `
		SELECT body::text, payload_sha256, created_at
		FROM cloudring_state.audit_journal
		WHERE scope = $1 AND event_id = $2
	`, scope, eventID).Scan(&stored, &payloadSHA256, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return auditEventRecord{}, ErrNotFound
	}
	if err != nil {
		return auditEventRecord{}, errors.New("read transactional state audit event")
	}
	event, err := scannedAuditEvent(scope, eventID, stored, createdAt)
	if err != nil {
		return auditEventRecord{}, err
	}
	return auditEventRecord{Event: event, PayloadSHA256: payloadSHA256}, nil
}

func scannedAuditEvent(scope, eventID, stored string, createdAt time.Time) (AuditEvent, error) {
	canonical, err := canonicalAuditJSON([]byte(stored))
	if err != nil {
		return AuditEvent{}, errors.New("stored transactional state audit event is invalid")
	}
	return AuditEvent{Scope: scope, ID: eventID, Value: canonical, CreatedAt: createdAt.UTC()}, nil
}

// ListAuditEvents returns at most pageSize events in ascending bytewise ID
// order. afterID is exclusive and may be empty for the first page.
func (store *Store) ListAuditEvents(ctx context.Context, scope, afterID string, pageSize int) (AuditEventPage, error) {
	if store == nil || store.pool == nil || ctx == nil || validateAuditList(scope, afterID, pageSize) != nil {
		return AuditEventPage{}, errors.New("transactional state audit list request is invalid")
	}
	queryCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	rows, err := store.pool.Query(queryCtx, `
		SELECT event_id, body::text, created_at
		FROM cloudring_state.audit_journal
		WHERE scope = $1 AND event_id > $2 COLLATE "C"
		ORDER BY event_id COLLATE "C" ASC
		LIMIT $3
	`, scope, afterID, pageSize+1)
	if err != nil {
		return AuditEventPage{}, errors.New("list transactional state audit events")
	}
	defer rows.Close()

	page := AuditEventPage{Events: make([]AuditEvent, 0, pageSize)}
	for rows.Next() {
		var eventID, stored string
		var createdAt time.Time
		if err := rows.Scan(&eventID, &stored, &createdAt); err != nil {
			return AuditEventPage{}, errors.New("scan transactional state audit events")
		}
		if len(page.Events) == pageSize {
			page.NextAfterID = page.Events[len(page.Events)-1].ID
			break
		}
		event, err := scannedAuditEvent(scope, eventID, stored, createdAt)
		if err != nil {
			return AuditEventPage{}, err
		}
		page.Events = append(page.Events, event)
	}
	if err := rows.Err(); err != nil {
		return AuditEventPage{}, errors.New("list transactional state audit events")
	}
	return page, nil
}

func validateAuditList(scope, afterID string, pageSize int) error {
	if !safeKeyPattern.MatchString(scope) || (afterID != "" && !safeKeyPattern.MatchString(afterID)) ||
		pageSize < 1 || pageSize > MaximumAuditPageSize {
		return errors.New("audit list input is invalid")
	}
	return nil
}

func canonicalAuditJSON(value []byte) ([]byte, error) {
	if len(value) == 0 || len(value) > MaximumAuditEventBytes {
		return nil, errors.New("audit JSON size is invalid")
	}
	canonical, err := canonicalJSON(value)
	if err != nil || len(canonical) > MaximumAuditEventBytes {
		return nil, errors.New("audit JSON is invalid")
	}
	return canonical, nil
}

func auditPayloadSHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
