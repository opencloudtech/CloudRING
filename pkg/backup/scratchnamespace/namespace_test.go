// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package scratchnamespace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type memoryState struct {
	values map[string]json.RawMessage
	fail   string
}

func (s *memoryState) Checkpoint(name string) (json.RawMessage, bool, error) {
	p, found := s.values[name]
	return bytes.Clone(p), found, nil
}
func (s *memoryState) WriteCheckpoint(name string, p json.RawMessage) error {
	if name == s.fail {
		return errors.New("simulated disk failure")
	}
	if previous, found := s.values[name]; found && !bytes.Equal(previous, p) {
		return errors.New("conflicting checkpoint")
	}
	s.values[name] = bytes.Clone(p)
	return nil
}

type fakeKubernetes struct {
	t               *testing.T
	state           *memoryState
	object          *namespaceObject
	creates         int
	deletes         int
	lostCreate      bool
	malformedCreate bool
	lostDelete      bool
	conflict        bool
	terminating     bool
	getError        bool
}

func (k *fakeKubernetes) Run(_ context.Context, args []string, input []byte) ([]byte, error) {
	k.t.Helper()
	switch args[0] {
	case "get":
		if strings.Join(args, " ") != "get namespace restore-test --ignore-not-found=true -o json" || len(input) != 0 {
			k.t.Fatalf("unexpected read: %q", args)
		}
		if k.getError {
			return nil, errors.New("simulated read failure")
		}
		if k.object == nil {
			return nil, nil
		}
		return json.Marshal(k.object)
	case "create":
		if _, found := k.state.values[createFenceKey]; !found {
			k.t.Fatal("create occurred before durable intent")
		}
		if len(args) > 1 && args[1] == "--dry-run=server" {
			return bytes.Clone(input), nil
		}
		if k.object != nil {
			return nil, errors.New("already exists")
		}
		var object namespaceObject
		if json.Unmarshal(input, &object) != nil {
			k.t.Fatal("invalid manifest")
		}
		object.Metadata.UID, object.Metadata.ResourceVersion = "uid-one", "10"
		k.object = &object
		k.creates++
		if k.lostCreate {
			return nil, errors.New("simulated lost create response")
		}
		if k.malformedCreate {
			return []byte(`{"kind":"Namespace"`), nil
		}
		return json.Marshal(object)
	case "delete":
		if strings.Join(args, " ") != "delete --raw /api/v1/namespaces/restore-test -f -" {
			k.t.Fatalf("delete must use exact API resource: %q", args)
		}
		var options struct {
			APIVersion    string `json:"apiVersion"`
			Kind          string `json:"kind"`
			Propagation   string `json:"propagationPolicy"`
			Preconditions struct {
				UID string `json:"uid"`
				RV  string `json:"resourceVersion"`
			} `json:"preconditions"`
		}
		if json.Unmarshal(input, &options) != nil || options.APIVersion != "v1" || options.Kind != "DeleteOptions" || options.Propagation != "Foreground" || k.object == nil {
			k.t.Fatal("invalid delete options")
		}
		journaled := false
		for name, p := range k.state.values {
			if !strings.HasPrefix(name, "scratch-delete-") {
				continue
			}
			var record createdRecord
			if json.Unmarshal(p, &record) == nil && record.Identity.UID == options.Preconditions.UID && record.Identity.ResourceVersion == options.Preconditions.RV {
				journaled = true
			}
		}
		if !journaled {
			k.t.Fatal("delete occurred before exact durable UID/resourceVersion intent")
		}
		k.deletes++
		if k.conflict {
			k.conflict = false
			k.object.Metadata.ResourceVersion = "12"
		}
		if options.Preconditions.UID != k.object.Metadata.UID || options.Preconditions.RV != k.object.Metadata.ResourceVersion {
			return nil, errors.New("conflict")
		}
		if k.terminating {
			timestamp := "2026-09-07T00:00:00Z"
			k.object.Metadata.DeletionTimestamp = &timestamp
		} else {
			k.object = nil
		}
		if k.lostDelete {
			return nil, errors.New("simulated lost delete response")
		}
		return []byte(`{"kind":"Status","status":"Success"}`), nil
	default:
		k.t.Fatalf("unexpected Kubernetes action: %q", args)
		return nil, nil
	}
}

func setup(t *testing.T) (Options, *fakeKubernetes, *memoryState) {
	t.Helper()
	state := &memoryState{values: make(map[string]json.RawMessage)}
	runner := &fakeKubernetes{t: t, state: state}
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	return Options{Binding: Binding{OperationID: "operation-one", Namespace: "restore-test", ScopeSHA256: strings.Repeat("a", 64)}, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}, State: state, Runner: runner, Now: func() time.Time { return now }, Sleep: func(ctx context.Context, duration time.Duration) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		now = now.Add(duration)
		return nil
	}}, runner, state
}

func create(t *testing.T, opts Options) Identity {
	t.Helper()
	id, err := Create(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestLostOrMalformedCreateResponseAdoptsOnlyFencedNamespace(t *testing.T) {
	for _, mode := range []string{"lost", "malformed", "normal"} {
		t.Run(mode, func(t *testing.T) {
			opts, runner, state := setup(t)
			runner.lostCreate = mode == "lost"
			runner.malformedCreate = mode == "malformed"
			id := create(t, opts)
			if id.UID != "uid-one" || runner.creates != 1 || runner.object.Metadata.Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
				t.Fatal("created identity or restricted policy was lost")
			}
			runner.object.Metadata.ResourceVersion = "11"
			if got := create(t, opts); got.UID != id.UID || runner.creates != 1 {
				t.Fatal("replay duplicated namespace")
			}
			receipt, err := Cleanup(context.Background(), opts)
			if err != nil || !validReceipt(receipt) || runner.object != nil || runner.deletes != 1 {
				t.Fatalf("cleanup failed: %+v, %v", receipt, err)
			}
			if _, ok := state.values[completedKey]; !ok {
				t.Fatal("cleanup was not durable")
			}
			if _, err := Create(context.Background(), opts); err == nil || runner.creates != 1 {
				t.Fatal("completed operation recreated namespace")
			}
		})
	}
}

func TestCrashAfterCreateBeforeIdentityCheckpointCanCleanUp(t *testing.T) {
	opts, runner, state := setup(t)
	state.fail = createdKey
	if _, err := Create(context.Background(), opts); err == nil || runner.creates != 1 {
		t.Fatal("expected post-create checkpoint failure")
	}
	if _, found := state.values[createdKey]; found {
		t.Fatal("identity was unexpectedly recorded")
	}
	state.fail = ""
	receipt, err := Cleanup(context.Background(), opts)
	if err != nil || !receipt.Complete || runner.object != nil {
		t.Fatalf("cleanup did not recover uncertain create: %v", err)
	}
}

func TestUnpersistedIntentCannotCreateOrDelete(t *testing.T) {
	opts, runner, state := setup(t)
	state.fail = createFenceKey
	if _, err := Create(context.Background(), opts); err == nil || runner.creates != 0 {
		t.Fatal("create escaped failed durable intent")
	}
	if _, err := Cleanup(context.Background(), opts); err == nil || runner.deletes != 0 {
		t.Fatal("cleanup accepted missing intent")
	}
}

func TestExistingNamespaceIsNeverAdoptedByName(t *testing.T) {
	opts, runner, state := setup(t)
	other := namespaceObject{APIVersion: "v1", Kind: "Namespace"}
	other.Metadata.Name = "restore-test"
	other.Metadata.UID = "foreign"
	other.Metadata.ResourceVersion = "4"
	runner.object = &other
	if _, err := Create(context.Background(), opts); err == nil || len(state.values) != 0 || runner.creates != 0 {
		t.Fatal("existing namespace acquired a create intent")
	}
	if _, err := Cleanup(context.Background(), opts); err == nil || runner.deletes != 0 {
		t.Fatal("foreign namespace was deleted")
	}
}

func TestReplacementOrOwnershipDriftCannotBeDeleted(t *testing.T) {
	for _, field := range []string{"uid", "nonce", "operation", "scope", "policy"} {
		t.Run(field, func(t *testing.T) {
			opts, runner, _ := setup(t)
			create(t, opts)
			switch field {
			case "uid":
				runner.object.Metadata.UID = "replacement"
			case "nonce":
				runner.object.Metadata.Annotations[nonceAnnotation] = strings.Repeat("b", 64)
			case "operation":
				runner.object.Metadata.Labels[operationLabel] = "another"
			case "scope":
				runner.object.Metadata.Annotations[scopeAnnotation] = strings.Repeat("b", 64)
			case "policy":
				runner.object.Metadata.Labels["pod-security.kubernetes.io/enforce"] = "privileged"
			}
			if _, err := Cleanup(context.Background(), opts); err == nil || runner.deletes != 0 {
				t.Fatalf("%s drift allowed deletion", field)
			}
			if _, err := Create(context.Background(), opts); err == nil || runner.creates != 1 {
				t.Fatalf("%s drift allowed adoption", field)
			}
		})
	}
}

func TestDeleteConflictRetainsIntentAndReplayUsesFreshVersion(t *testing.T) {
	opts, runner, state := setup(t)
	create(t, opts)
	runner.conflict = true
	if _, err := Cleanup(context.Background(), opts); err == nil || runner.object == nil {
		t.Fatal("conflicting delete unexpectedly succeeded")
	}
	if _, found := state.values[completedKey]; found {
		t.Fatal("failed cleanup was recorded complete")
	}
	if _, err := Cleanup(context.Background(), opts); err != nil || runner.object != nil || runner.deletes != 2 {
		t.Fatalf("fresh exact-version cleanup failed: %v", err)
	}
	intents := 0
	for name := range state.values {
		if strings.HasPrefix(name, "scratch-delete-") {
			intents++
		}
	}
	if intents != 2 {
		t.Fatal("delete replay replaced old intent")
	}
}

func TestLostDeleteResponseIsResolvedByAbsence(t *testing.T) {
	opts, runner, _ := setup(t)
	create(t, opts)
	runner.lostDelete = true
	if receipt, err := Cleanup(context.Background(), opts); err != nil || !receipt.Complete {
		t.Fatalf("lost delete response remained unresolved: %v", err)
	}
}

func TestQuietWindowRejectsRecreation(t *testing.T) {
	opts, runner, state := setup(t)
	create(t, opts)
	copy := *runner.object
	sleep := opts.Sleep
	opts.Sleep = func(ctx context.Context, duration time.Duration) error {
		if duration == QuietWindow {
			runner.object = &copy
		}
		return sleep(ctx, duration)
	}
	if _, err := Cleanup(context.Background(), opts); err == nil {
		t.Fatal("second sweep accepted recreated namespace")
	}
	if _, found := state.values[completedKey]; found {
		t.Fatal("failed quiet window was recorded complete")
	}
}

func TestCompletedCleanupRejectsLaterReplacement(t *testing.T) {
	opts, runner, _ := setup(t)
	create(t, opts)
	copy := *runner.object
	first, err := Cleanup(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Cleanup(context.Background(), opts)
	if err != nil || second.CompletedAt != first.CompletedAt || runner.deletes != 1 {
		t.Fatal("cleanup replay changed completion evidence")
	}
	copy.Metadata.UID = "replacement"
	runner.object = &copy
	if _, err := Cleanup(context.Background(), opts); err == nil || runner.deletes != 1 {
		t.Fatal("completed cleanup deleted later replacement")
	}
}

func TestCancellationWhileTerminatingCanResumeWithoutAnotherDelete(t *testing.T) {
	opts, runner, _ := setup(t)
	create(t, opts)
	runner.terminating = true
	sleep := opts.Sleep
	opts.Sleep = func(context.Context, time.Duration) error { return context.Canceled }
	if _, err := Cleanup(context.Background(), opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled wait, got %v", err)
	}
	opts.Sleep = func(ctx context.Context, duration time.Duration) error {
		runner.object = nil
		return sleep(ctx, duration)
	}
	if receipt, err := Cleanup(context.Background(), opts); err != nil || !receipt.Complete || runner.deletes != 1 {
		t.Fatalf("terminating cleanup could not resume: %v", err)
	}
}

func TestBindingDriftAndMalformedCheckpointFailBeforeMutation(t *testing.T) {
	for _, mutation := range []string{"binding", "duplicate", "unknown", "labels"} {
		t.Run(mutation, func(t *testing.T) {
			opts, runner, state := setup(t)
			create(t, opts)
			switch mutation {
			case "binding":
				opts.Binding.ScopeSHA256 = strings.Repeat("b", 64)
			case "duplicate":
				state.values[createFenceKey] = []byte(`{"schemaVersion":"one","schemaVersion":"two"}`)
			case "unknown":
				state.values[createdKey] = []byte(`{"extra":1}`)
			case "labels":
				opts.Labels["pod-security.kubernetes.io/enforce"] = "baseline"
			}
			if _, err := Create(context.Background(), opts); err == nil || runner.creates != 1 {
				t.Fatal("changed checkpoint or binding allowed creation")
			}
			if mutation != "labels" {
				if _, err := Cleanup(context.Background(), opts); err == nil || runner.deletes != 0 {
					t.Fatal("changed checkpoint or binding allowed cleanup")
				}
			}
		})
	}
}
