// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package restoreproof

import (
	"encoding/json"
	"testing"
)

func TestCanonicalKubernetesStatePreservesIntegersAndIgnoresTransportMetadata(t *testing.T) {
	t.Parallel()
	left := map[string]any{
		"apiVersion": "v1", "kind": "Example",
		"metadata": map[string]any{"name": "one", "resourceVersion": "1", "managedFields": []any{"left"}, "creationTimestamp": "2026-01-01T00:00:00Z"},
		"spec":     map[string]any{"bytes": json.Number("9007199254740993")},
	}
	right := map[string]any{
		"apiVersion": "v1", "kind": "Example",
		"metadata": map[string]any{"name": "one", "resourceVersion": "2", "managedFields": []any{"right"}, "creationTimestamp": "2026-02-01T00:00:00Z"},
		"spec":     map[string]any{"bytes": json.Number("9007199254740993")},
	}
	leftDigest, err := CanonicalKubernetesStateSHA256(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := CanonicalKubernetesStateSHA256(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatal("transport-only metadata changed the canonical state")
	}
	right["spec"].(map[string]any)["bytes"] = json.Number("9007199254740994")
	changed, err := CanonicalKubernetesStateSHA256(right)
	if err != nil {
		t.Fatal(err)
	}
	if changed == leftDigest {
		t.Fatal("semantic integer change did not change the canonical state")
	}
}
