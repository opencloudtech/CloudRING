// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package drill

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/opencloudtech/CloudRING/internal/privateartifact"
	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const maxJournalBytes = 2 << 20

func CreateJournal(path string, entry JournalEntry) error {
	if entry.Sequence != 1 || entry.Step != ApplySteps[0] || entry.PreviousEntrySHA256 != "" {
		return errors.New("backup drill initial journal entry is invalid")
	}
	if err := validateJournalEntry(entry, nil); err != nil {
		return err
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return errors.New("encode backup drill journal entry")
	}
	payload = append(payload, '\n')
	return privateartifact.WriteNew(path, payload)
}

func AppendJournal(path string, entry JournalEntry) error {
	transaction, err := openJournalTransaction(path)
	if err != nil {
		return err
	}
	defer transaction.close()
	return transaction.append(entry)
}

func LoadJournal(path string) ([]JournalEntry, error) {
	transaction, err := openJournalTransaction(path)
	if err != nil {
		return nil, err
	}
	defer transaction.close()
	entries, _, err := transaction.load()
	return entries, err
}

type journalTransaction struct {
	path string
	root *os.Root
	file *os.File
}

func openJournalTransaction(path string) (*journalTransaction, error) {
	clean, root, name, selected, err := openJournalRoot(path)
	if err != nil {
		return nil, err
	}
	file, err := root.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return nil, errors.Join(errors.New("open backup drill journal transaction"), root.Close())
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(selected, opened) || !protectedJournalFile(opened) {
		return nil, errors.Join(errors.New("backup drill journal transaction inode is invalid"), file.Close(), root.Close())
	}
	if err := lockJournalFile(file); err != nil {
		return nil, errors.Join(errors.New("lock backup drill journal transaction"), file.Close(), root.Close())
	}
	afterPath, pathErr := os.Lstat(clean)
	afterOpen, openErr := file.Stat()
	if pathErr != nil || openErr != nil || !os.SameFile(opened, afterPath) || !os.SameFile(opened, afterOpen) || !protectedJournalFile(afterPath) || !protectedJournalFile(afterOpen) {
		return nil, errors.Join(errors.New("backup drill journal changed while acquiring lock"), unlockJournalFile(file), file.Close(), root.Close())
	}
	return &journalTransaction{path: clean, root: root, file: file}, nil
}

func (transaction *journalTransaction) close() error {
	if transaction == nil {
		return nil
	}
	unlockErr := unlockJournalFile(transaction.file)
	fileErr := transaction.file.Close()
	rootErr := transaction.root.Close()
	return errors.Join(unlockErr, fileErr, rootErr)
}

func (transaction *journalTransaction) load() ([]JournalEntry, int64, error) {
	if transaction == nil || transaction.file == nil {
		return nil, 0, errors.New("backup drill journal transaction is unavailable")
	}
	opened, statErr := transaction.file.Stat()
	pathBefore, pathErr := os.Lstat(transaction.path)
	if statErr != nil || pathErr != nil || !sameJournalMetadata(opened, pathBefore) || opened.Size() < 2 || opened.Size() > maxJournalBytes {
		return nil, 0, errors.New("backup drill journal input is invalid")
	}
	if _, err := transaction.file.Seek(0, io.SeekStart); err != nil {
		return nil, 0, errors.New("seek backup drill journal")
	}
	payload, readErr := io.ReadAll(io.LimitReader(transaction.file, maxJournalBytes+1))
	afterOpen, afterErr := transaction.file.Stat()
	afterPath, afterPathErr := os.Lstat(transaction.path)
	if readErr != nil || afterErr != nil || afterPathErr != nil || !sameJournalMetadata(opened, afterOpen) || !sameJournalMetadata(opened, afterPath) ||
		int64(len(payload)) != opened.Size() || len(payload) > maxJournalBytes || payload[len(payload)-1] != '\n' {
		return nil, 0, errors.New("backup drill journal changed or is truncated")
	}
	defer zero(payload)
	entries, err := decodeJournal(payload)
	return entries, opened.Size(), err
}

func decodeJournal(payload []byte) ([]JournalEntry, error) {
	lines := bytes.Split(payload[:len(payload)-1], []byte{'\n'})
	if len(lines) == 0 || len(lines) > 32 {
		return nil, errors.New("backup drill journal entry count is invalid")
	}
	entries := make([]JournalEntry, 0, len(lines))
	for _, line := range lines {
		var entry JournalEntry
		if err := strictjson.DecodeExact(line, &entry); err != nil {
			return nil, errors.New("backup drill journal contains invalid JSON")
		}
		var previous *JournalEntry
		if len(entries) > 0 {
			previous = &entries[len(entries)-1]
		}
		if err := validateJournalEntry(entry, previous); err != nil || !validTransition(entries, entry.Step) {
			return nil, errors.New("backup drill journal chain is invalid")
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func validateJournalEntries(entries []JournalEntry) error {
	if len(entries) == 0 || len(entries) > 32 {
		return errors.New("backup drill journal entry count is invalid")
	}
	validated := make([]JournalEntry, 0, len(entries))
	for _, entry := range entries {
		var previous *JournalEntry
		if len(validated) > 0 {
			previous = &validated[len(validated)-1]
		}
		if err := validateJournalEntry(entry, previous); err != nil || !validTransition(validated, entry.Step) {
			return errors.New("backup drill journal chain is invalid")
		}
		validated = append(validated, entry)
	}
	return nil
}

func (transaction *journalTransaction) append(entry JournalEntry) error {
	entries, loadedSize, err := transaction.load()
	if err != nil || len(entries) == 0 {
		return errors.New("load backup drill journal before append")
	}
	if err := validateJournalEntry(entry, &entries[len(entries)-1]); err != nil || !validTransition(entries, entry.Step) {
		return errors.New("backup drill journal append is not a valid transition")
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return errors.New("encode backup drill journal entry")
	}
	payload = append(payload, '\n')
	if len(payload) > 128*1024 || loadedSize+int64(len(payload)) > maxJournalBytes {
		return errors.New("backup drill journal entry exceeds limit")
	}
	opened, statErr := transaction.file.Stat()
	pathInfo, pathErr := os.Lstat(transaction.path)
	if statErr != nil || pathErr != nil || opened.Size() != loadedSize || !sameJournalMetadata(opened, pathInfo) {
		return errors.New("backup drill journal changed before append")
	}
	if _, err := transaction.file.Seek(loadedSize, io.SeekStart); err != nil {
		return errors.New("seek backup drill journal append")
	}
	if _, err := transaction.file.Write(payload); err != nil {
		return errors.New("append backup drill journal")
	}
	if err := transaction.file.Sync(); err != nil {
		return errors.New("sync backup drill journal")
	}
	expectedSize := loadedSize + int64(len(payload))
	afterOpen, afterErr := transaction.file.Stat()
	afterPath, afterPathErr := os.Lstat(transaction.path)
	if afterErr != nil || afterPathErr != nil || afterOpen.Size() != expectedSize || !sameJournalMetadata(afterOpen, afterPath) {
		return errors.New("backup drill journal changed after append")
	}
	directory, err := os.Open(filepath.Dir(transaction.path))
	if err != nil {
		return errors.New("open backup drill journal directory")
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("sync backup drill journal directory")
	}
	return nil
}

func sameJournalMetadata(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && protectedJournalFile(left) && protectedJournalFile(right) &&
		left.Mode() == right.Mode() && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

func openJournalRoot(path string) (string, *os.Root, string, os.FileInfo, error) {
	clean, err := filepath.Abs(filepath.Clean(path))
	if err != nil || !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return "", nil, "", nil, errors.New("backup drill journal path is invalid")
	}
	selected, err := os.Lstat(clean)
	if err != nil || !protectedJournalFile(selected) || selected.Size() < 1 || selected.Size() > maxJournalBytes {
		return "", nil, "", nil, errors.New("backup drill journal is not an exact owner-only regular file")
	}
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return "", nil, "", nil, errors.New("open backup drill journal directory")
	}
	return clean, root, filepath.Base(clean), selected, nil
}

func validateJournalEntry(entry JournalEntry, previous *JournalEntry) error {
	if entry.SchemaVersion != JournalEntryVersion || entry.Sequence < 1 || !validID(entry.OperationID) || !validSHA(entry.PlanSHA256) ||
		!validSHA(entry.ApprovalSHA256) || !validSHA(entry.ApprovalScopeSHA256) || !validSHA(entry.AdapterExecutableSHA256) ||
		!validID(entry.Step) || !validSHA(entry.RequestSHA256) || !validSHA(entry.ResponseSHA256) || entry.EntrySHA256 != JournalEntrySHA256(entry) {
		return errors.New("backup drill journal entry is invalid")
	}
	if entry.Response != nil && (entry.Response.ResponseSHA256 != entry.ResponseSHA256 || entry.Response.ResponseSHA256 != AdapterResponseSHA256(*entry.Response)) {
		return errors.New("backup drill journal response is not hash-bound")
	}
	if _, err := canonicalTime(entry.RecordedAt); err != nil {
		return errors.New("backup drill journal entry time is invalid")
	}
	if previous == nil {
		if entry.Sequence != 1 || entry.PreviousEntrySHA256 != "" {
			return errors.New("backup drill journal does not start at sequence one")
		}
		return nil
	}
	previousTime, previousTimeErr := canonicalTime(previous.RecordedAt)
	entryTime, entryTimeErr := canonicalTime(entry.RecordedAt)
	if previousTimeErr != nil || entryTimeErr != nil || entryTime.Before(previousTime) || entry.Sequence != previous.Sequence+1 || entry.PreviousEntrySHA256 != previous.EntrySHA256 || entry.OperationID != previous.OperationID ||
		entry.PlanSHA256 != previous.PlanSHA256 || entry.ApprovalSHA256 != previous.ApprovalSHA256 || entry.ApprovalScopeSHA256 != previous.ApprovalScopeSHA256 ||
		entry.AdapterExecutableSHA256 != previous.AdapterExecutableSHA256 {
		return errors.New("backup drill journal entry changed transaction binding")
	}
	return nil
}

func validTransition(entries []JournalEntry, next string) bool {
	if len(entries) == 0 {
		return next == ApplySteps[0]
	}
	for _, entry := range entries {
		if entry.Step == next {
			return false
		}
	}
	last := entries[len(entries)-1].Step
	if last == "rolled-back" || last == "rollback-failed" || last == "completed" {
		return false
	}
	if last == "rollback-safe-stop" {
		return next == "rollback-cleanup-requested" || next == "rollback-failed"
	}
	if last == "rollback-cleanup-requested" {
		return next == "rolled-back" || next == "rollback-failed"
	}
	if slices.Contains([]string{"rolled-back", "rollback-failed"}, next) {
		return false
	}
	if next == "rollback-safe-stop" {
		return true
	}
	return len(entries) < len(ApplySteps) && next == ApplySteps[len(entries)]
}

func newJournalEntry(now time.Time, sequence int, plan Plan, approval ApprovalReport, step, requestSHA, responseSHA, previous string, response *AdapterResponse) JournalEntry {
	entry := JournalEntry{
		SchemaVersion: JournalEntryVersion, Sequence: sequence, OperationID: plan.OperationID, PlanSHA256: PlanSHA256(plan),
		ApprovalSHA256: ApprovalSHA256(approval), ApprovalScopeSHA256: ApprovalScopeSHA256(plan), AdapterExecutableSHA256: plan.Adapter.ExecutableSHA256,
		Step: step, RequestSHA256: requestSHA, ResponseSHA256: responseSHA, PreviousEntrySHA256: previous,
		Response:   response,
		RecordedAt: now.UTC().Format(time.RFC3339Nano),
	}
	entry.EntrySHA256 = JournalEntrySHA256(entry)
	return entry
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
