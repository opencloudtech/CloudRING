// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Package scratchnamespace owns one isolated restore namespace through a
// durable create fence and exact Kubernetes deletion preconditions. It never
// adopts a namespace using its name alone. Callers supply their existing
// operation checkpoint store and retain it until cleanup is verified.
package scratchnamespace

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const (
	schema          = "cloudring.backup.scratch-namespace/v1"
	operationLabel  = "cloudring.io/restore-operation"
	nonceAnnotation = "cloudring.io/restore-create-nonce"
	scopeAnnotation = "cloudring.io/restore-scope-sha256"
	createFenceKey  = "scratch-namespace-create-intent"
	createdKey      = "scratch-namespace-created"
	completedKey    = "scratch-namespace-cleanup-completed"
	QuietWindow     = 30 * time.Second
)

var namePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// State is satisfied by the adapter's write-once, fsync-backed checkpoint
// store. WriteCheckpoint must reject a different value at an existing name.
// Callers must serialize users of one operation's state, including cleanup.
type State interface {
	Checkpoint(string) (json.RawMessage, bool, error)
	WriteCheckpoint(string, json.RawMessage) error
}

type Runner interface {
	Run(context.Context, []string, []byte) ([]byte, error)
}

type Binding struct {
	OperationID string `json:"operationId"`
	Namespace   string `json:"namespace"`
	ScopeSHA256 string `json:"scopeSha256"`
}

type Options struct {
	Binding Binding
	Labels  map[string]string
	State   State
	Runner  Runner
	Now     func() time.Time
	Sleep   func(context.Context, time.Duration) error
}

type Identity struct {
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
}

type Sweep struct {
	ObservedAt      string `json:"observedAt"`
	InventorySHA256 string `json:"inventorySha256"`
	NamespaceCount  int    `json:"namespaceCount"`
}

type CleanupReceipt struct {
	StartedAt                  string  `json:"startedAt"`
	CompletedAt                string  `json:"completedAt"`
	Complete                   bool    `json:"complete"`
	TwoSweepQuietWindowSeconds int     `json:"twoSweepQuietWindowSeconds"`
	Sweeps                     []Sweep `json:"sweeps"`
}

type createFence struct {
	SchemaVersion string            `json:"schemaVersion"`
	Binding       Binding           `json:"binding"`
	Nonce         string            `json:"nonce"`
	Labels        map[string]string `json:"labels,omitempty"`
}

type createdRecord struct {
	Binding  Binding  `json:"binding"`
	Identity Identity `json:"identity"`
}

type cleanupRecord struct {
	Binding Binding        `json:"binding"`
	Receipt CleanupReceipt `json:"receipt"`
}

type namespaceObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name              string            `json:"name"`
		UID               string            `json:"uid"`
		ResourceVersion   string            `json:"resourceVersion"`
		DeletionTimestamp *string           `json:"deletionTimestamp"`
		Labels            map[string]string `json:"labels"`
		Annotations       map[string]string `json:"annotations"`
	} `json:"metadata"`
}

// Create persists the namespace manifest identity before submitting a create.
// On replay or an uncertain response, it adopts only the matching durable
// random nonce and approval scope; an already checkpointed UID cannot change.
func Create(ctx context.Context, opts Options) (Identity, error) {
	if err := validate(ctx, opts); err != nil {
		return Identity{}, err
	}
	var fence createFence
	found, err := read(opts.State, createFenceKey, &fence)
	if err != nil {
		return Identity{}, err
	}
	if !found {
		_, present, err := get(ctx, opts)
		if err != nil || present {
			return Identity{}, errors.New("scratch namespace was not proved absent")
		}
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return Identity{}, errors.New("generate scratch namespace create nonce")
		}
		fence = createFence{SchemaVersion: schema, Binding: opts.Binding, Nonce: hex.EncodeToString(nonce[:]), Labels: maps.Clone(opts.Labels)}
		if err := write(opts.State, createFenceKey, fence); err != nil {
			return Identity{}, err
		}
	}
	if err := validateFence(fence, opts.Binding); err != nil || !maps.Equal(fence.Labels, opts.Labels) {
		return Identity{}, errors.New("scratch namespace create intent or labels changed")
	}
	var completed cleanupRecord
	if found, err := read(opts.State, completedKey, &completed); err != nil || found {
		return Identity{}, errors.New("scratch namespace operation is already cleaned up or unreadable")
	}
	var recorded createdRecord
	hasIdentity, err := read(opts.State, createdKey, &recorded)
	if err != nil || hasIdentity && !validCreated(recorded, opts.Binding) {
		return Identity{}, errors.New("scratch namespace recorded identity is invalid")
	}
	object, present, err := get(ctx, opts)
	if err != nil {
		return Identity{}, err
	}
	if !present {
		if hasIdentity {
			return Identity{}, errors.New("previously created scratch namespace is absent")
		}
		labels := maps.Clone(fence.Labels)
		if labels == nil {
			labels = make(map[string]string)
		}
		labels[operationLabel] = opts.Binding.OperationID
		manifest := map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{
			"name":        opts.Binding.Namespace,
			"labels":      labels,
			"annotations": map[string]string{nonceAnnotation: fence.Nonce, scopeAnnotation: opts.Binding.ScopeSHA256},
		}}
		input, _ := json.Marshal(manifest)
		dryRunOutput, dryRunErr := opts.Runner.Run(ctx, []string{"create", "--dry-run=server", "-f", "-", "-o", "json"}, input)
		clear(dryRunOutput)
		if dryRunErr != nil {
			clear(input)
			return Identity{}, errors.New("scratch namespace server dry-run was rejected")
		}
		output, createErr := opts.Runner.Run(ctx, []string{"create", "-f", "-", "-o", "json"}, input)
		clear(input)
		decodeErr := strictjson.Decode(output, &object)
		clear(output)
		if createErr != nil || decodeErr != nil || !owned(object, fence) {
			// A server may have committed the create even if its response was
			// lost or malformed. The durable fence, never an error string,
			// identifies the only namespace that cleanup may adopt.
			object, present, err = get(ctx, opts)
			if err != nil || !present {
				return Identity{}, errors.New("scratch namespace create outcome is uncertain; replay cleanup")
			}
		}
	}
	if !owned(object, fence) || object.Metadata.DeletionTimestamp != nil {
		return Identity{}, errors.New("scratch namespace create identity or ownership changed")
	}
	identity := objectIdentity(object)
	if hasIdentity {
		if identity.UID != recorded.Identity.UID {
			return Identity{}, errors.New("scratch namespace was replaced")
		}
		return identity, nil
	}
	if err := write(opts.State, createdKey, createdRecord{Binding: opts.Binding, Identity: identity}); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

// Cleanup can be called after Create returns any error, or from a later
// cleanup-only invocation after process death. A missing create intent never
// authorizes deletion. The latest resourceVersion is journaled before each
// exact delete, so legitimate status updates can be handled on a later replay
// without weakening the original UID fence.
func Cleanup(ctx context.Context, opts Options) (CleanupReceipt, error) {
	if err := validate(ctx, opts); err != nil {
		return CleanupReceipt{}, err
	}
	var fence createFence
	found, err := read(opts.State, createFenceKey, &fence)
	if err != nil || !found || validateFence(fence, opts.Binding) != nil {
		return CleanupReceipt{}, errors.New("scratch namespace create intent is absent or invalid")
	}
	var recorded createdRecord
	hasIdentity, err := read(opts.State, createdKey, &recorded)
	if err != nil || hasIdentity && !validCreated(recorded, opts.Binding) {
		return CleanupReceipt{}, errors.New("scratch namespace recorded identity is invalid")
	}
	var completed cleanupRecord
	isComplete, err := read(opts.State, completedKey, &completed)
	if err != nil || isComplete && (completed.Binding != opts.Binding || !validReceipt(completed.Receipt) || completed.Receipt.Sweeps[0].InventorySHA256 != absentInventory(opts.Binding.Namespace)) {
		return CleanupReceipt{}, errors.New("scratch namespace cleanup checkpoint is invalid")
	}
	started := opts.Now().UTC()
	object, present, err := get(ctx, opts)
	if err != nil {
		return CleanupReceipt{}, err
	}
	if isComplete {
		if present {
			return CleanupReceipt{}, errors.New("cleaned scratch namespace is present again")
		}
		return completed.Receipt, nil
	}
	if present {
		if !owned(object, fence) || hasIdentity && object.Metadata.UID != recorded.Identity.UID {
			return CleanupReceipt{}, errors.New("scratch namespace cleanup ownership or UID changed")
		}
		identity := objectIdentity(object)
		if !hasIdentity {
			recorded = createdRecord{Binding: opts.Binding, Identity: identity}
			if err := write(opts.State, createdKey, recorded); err != nil {
				return CleanupReceipt{}, err
			}
		}
		if object.Metadata.DeletionTimestamp == nil {
			intent, _ := json.Marshal(createdRecord{Binding: opts.Binding, Identity: identity})
			digest := sha256.Sum256(intent)
			if err := opts.State.WriteCheckpoint("scratch-delete-"+hex.EncodeToString(digest[:]), intent); err != nil {
				return CleanupReceipt{}, errors.New("persist scratch namespace delete intent")
			}
			options, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground", "preconditions": map[string]string{"uid": identity.UID, "resourceVersion": identity.ResourceVersion}})
			output, deleteErr := opts.Runner.Run(ctx, []string{"delete", "--raw", "/api/v1/namespaces/" + opts.Binding.Namespace, "-f", "-"}, options)
			clear(options)
			clear(output)
			if deleteErr != nil {
				// Keep the intent even when the response is lost. A fresh GET
				// must prove absence or the same UID already terminating.
				current, remains, readErr := get(ctx, opts)
				if readErr != nil || remains && (!owned(current, fence) || current.Metadata.UID != identity.UID || current.Metadata.DeletionTimestamp == nil) {
					return CleanupReceipt{}, errors.New("scratch namespace delete outcome is uncertain; replay cleanup")
				}
			}
		}
		deadline := opts.Now().Add(15 * time.Minute)
		for {
			current, remains, err := get(ctx, opts)
			if err != nil {
				return CleanupReceipt{}, err
			}
			if !remains {
				break
			}
			if !owned(current, fence) || current.Metadata.UID != identity.UID {
				return CleanupReceipt{}, errors.New("scratch namespace was replaced during cleanup")
			}
			if !opts.Now().Before(deadline) {
				return CleanupReceipt{}, errors.New("scratch namespace deletion did not complete")
			}
			if err := opts.Sleep(ctx, 2*time.Second); err != nil {
				return CleanupReceipt{}, err
			}
		}
	}
	receipt := CleanupReceipt{StartedAt: started.Format(time.RFC3339Nano), Complete: true, TwoSweepQuietWindowSeconds: int(QuietWindow / time.Second)}
	for index := 0; index < 2; index++ {
		if index > 0 {
			if err := opts.Sleep(ctx, QuietWindow); err != nil {
				return CleanupReceipt{}, err
			}
		}
		_, present, err := get(ctx, opts)
		if err != nil || present {
			return CleanupReceipt{}, errors.New("scratch namespace absence sweep failed")
		}
		receipt.Sweeps = append(receipt.Sweeps, Sweep{ObservedAt: opts.Now().UTC().Format(time.RFC3339Nano), InventorySHA256: absentInventory(opts.Binding.Namespace), NamespaceCount: 0})
	}
	receipt.CompletedAt = opts.Now().UTC().Format(time.RFC3339Nano)
	if !validReceipt(receipt) {
		return CleanupReceipt{}, errors.New("scratch namespace quiet window was not observed")
	}
	if err := write(opts.State, completedKey, cleanupRecord{Binding: opts.Binding, Receipt: receipt}); err != nil {
		return CleanupReceipt{}, err
	}
	return receipt, nil
}

func validate(ctx context.Context, opts Options) error {
	if ctx == nil || opts.State == nil || opts.Runner == nil || opts.Now == nil || opts.Sleep == nil || !namePattern.MatchString(opts.Binding.OperationID) || !namePattern.MatchString(opts.Binding.Namespace) || !validSHA(opts.Binding.ScopeSHA256) || opts.Labels[operationLabel] != "" && opts.Labels[operationLabel] != opts.Binding.OperationID {
		return errors.New("scratch namespace options are invalid")
	}
	return nil
}

func validSHA(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}
func validateFence(fence createFence, binding Binding) error {
	if fence.SchemaVersion != schema || fence.Binding != binding || !validSHA(fence.Nonce) {
		return errors.New("scratch namespace create intent does not match the operation")
	}
	return nil
}

func validCreated(record createdRecord, binding Binding) bool {
	return record.Binding == binding && record.Identity.Name == binding.Namespace && record.Identity.UID != "" && record.Identity.ResourceVersion != ""
}

func objectIdentity(object namespaceObject) Identity {
	return Identity{Name: object.Metadata.Name, UID: object.Metadata.UID, ResourceVersion: object.Metadata.ResourceVersion}
}
func owned(object namespaceObject, fence createFence) bool {
	for key, value := range fence.Labels {
		if object.Metadata.Labels[key] != value {
			return false
		}
	}
	return object.APIVersion == "v1" && object.Kind == "Namespace" && object.Metadata.Name == fence.Binding.Namespace && object.Metadata.UID != "" && object.Metadata.ResourceVersion != "" && object.Metadata.Labels[operationLabel] == fence.Binding.OperationID && object.Metadata.Annotations[nonceAnnotation] == fence.Nonce && object.Metadata.Annotations[scopeAnnotation] == fence.Binding.ScopeSHA256
}

func get(ctx context.Context, opts Options) (namespaceObject, bool, error) {
	payload, err := opts.Runner.Run(ctx, []string{"get", "namespace", opts.Binding.Namespace, "--ignore-not-found=true", "-o", "json"}, nil)
	defer clear(payload)
	if err != nil {
		return namespaceObject{}, false, errors.New("read exact scratch namespace")
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		return namespaceObject{}, false, nil
	}
	var object namespaceObject
	if len(payload) > 2<<20 || strictjson.Decode(payload, &object) != nil || object.APIVersion != "v1" || object.Kind != "Namespace" || object.Metadata.Name != opts.Binding.Namespace || object.Metadata.UID == "" || object.Metadata.ResourceVersion == "" {
		return namespaceObject{}, false, errors.New("scratch namespace response is invalid")
	}
	return object, true, nil
}

func read(state State, name string, destination any) (bool, error) {
	payload, found, err := state.Checkpoint(name)
	defer clear(payload)
	if err != nil {
		return false, errors.New("read scratch namespace checkpoint")
	}
	if !found {
		return false, nil
	}
	if len(payload) > 2<<20 || strictjson.DecodeExact(payload, destination) != nil {
		return false, errors.New("scratch namespace checkpoint is invalid")
	}
	return true, nil
}

func write(state State, name string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return errors.New("encode scratch namespace checkpoint")
	}
	defer clear(payload)
	if err := state.WriteCheckpoint(name, payload); err != nil {
		return errors.New("persist scratch namespace checkpoint")
	}
	return nil
}

func validReceipt(receipt CleanupReceipt) bool {
	if !receipt.Complete || receipt.TwoSweepQuietWindowSeconds != int(QuietWindow/time.Second) || len(receipt.Sweeps) != 2 {
		return false
	}
	start, a := time.Parse(time.RFC3339Nano, receipt.StartedAt)
	end, b := time.Parse(time.RFC3339Nano, receipt.CompletedAt)
	first, c := time.Parse(time.RFC3339Nano, receipt.Sweeps[0].ObservedAt)
	second, d := time.Parse(time.RFC3339Nano, receipt.Sweeps[1].ObservedAt)
	return a == nil && b == nil && c == nil && d == nil && !first.Before(start) && !end.Before(second) && second.Sub(first) >= QuietWindow && receipt.Sweeps[0].NamespaceCount == 0 && receipt.Sweeps[1].NamespaceCount == 0 && receipt.Sweeps[0].InventorySHA256 == receipt.Sweeps[1].InventorySHA256
}

func absentInventory(namespace string) string {
	digest := sha256.Sum256([]byte(namespace + "/0"))
	return "sha256:" + hex.EncodeToString(digest[:])
}
