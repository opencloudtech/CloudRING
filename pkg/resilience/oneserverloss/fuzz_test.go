// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package oneserverloss

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

type fuzzListReader struct{ payload []byte }

func (reader fuzzListReader) IdentitySHA256() string       { return testDigest("fuzz-reader") }
func (reader fuzzListReader) ReadyZ(context.Context) error { return nil }
func (reader fuzzListReader) Get(context.Context, Resource, string, string) ([]byte, error) {
	return nil, ErrNotFound
}
func (reader fuzzListReader) ListPage(context.Context, Resource, string, string, string, int) ([]byte, error) {
	return reader.payload, nil
}

func FuzzKubernetesListDecoder(fuzzer *testing.F) {
	fuzzer.Add([]byte(`{"apiVersion":"v1","kind":"NodeList","metadata":{"resourceVersion":"1"},"items":[]}`))
	fuzzer.Add([]byte(`{"apiVersion":"v1","kind":"NodeList","metadata":{"resourceVersion":"1"},"items":[{"apiVersion":"v1","kind":"Node","metadata":{"name":"node-1","uid":"uid-1","resourceVersion":"1"}}]}`))
	fuzzer.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = listAll(context.Background(), fuzzListReader{payload: payload}, nodeResource, "", "")
	})
}

func FuzzDataProbeResponseDecoder(fuzzer *testing.F) {
	request := ProbeRequest{
		SchemaVersion: ProbeRequestSchemaVersion, RunNonceSHA256: testDigest("nonce"), ParentRequestSHA256: testDigest("request"),
		Phase: PhasePreLoss, Sequence: 1, ProbeID: "business-state", QueryRef: "canonical-state", AdapterExecutableSHA256: testDigest("adapter"),
	}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	seed, err := json.Marshal(ProbeResponse{
		SchemaVersion: ProbeResponseSchemaVersion, Implementation: "postgresql-probe", Version: "v1", RequestSHA256: digestJSON(request),
		AdapterExecutableSHA256: request.AdapterExecutableSHA256, HashAlgorithm: "sha256", DataSHA256: testDigest("data"), ValidatedBytes: 1024,
		StartedAt: now, CompletedAt: now,
	})
	if err != nil {
		fuzzer.Fatal(err)
	}
	fuzzer.Add(seed)
	fuzzer.Fuzz(func(t *testing.T, payload []byte) {
		var response ProbeResponse
		if strictjson.DecodeExact(payload, &response) == nil {
			_ = validateProbeResponse(request, response, 1)
		}
	})
}
