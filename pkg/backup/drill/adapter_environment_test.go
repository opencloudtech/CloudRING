// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package drill

import (
	"encoding/json"
	"testing"
)

func TestAdapterRejectsRawAndJSONEscapedEnvironmentValues(t *testing.T) {
	value := "synthetic-credential-\"<&>\n"
	adapter := &Adapter{environment: []string{"PROVIDER_KEY=" + value}}
	encoded, err := json.Marshal(map[string]string{"ref": "evidence/" + value})
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range [][]byte{[]byte(value), encoded} {
		if !adapter.containsEnvironmentValue(output) {
			t.Fatal("selected value was not rejected")
		}
	}
	if adapter.containsEnvironmentValue([]byte(`{"ref":"evidence/safe"}`)) {
		t.Fatal("unrelated response rejected")
	}
}
