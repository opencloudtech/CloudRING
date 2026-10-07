// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package kubeidentity

import (
	"strings"
	"testing"
)

func TestNodeUIDSHA256FixedVectors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		uid  string
		want string
	}{
		{name: "uuid", uid: "550e8400-e29b-41d4-a716-446655440000", want: "0d754603fbf7bcba0e2515a5693ce45cbc43081517b0bc9bf9ca8ea8bf3565c6"},
		{name: "case and spaces are exact", uid: " Node-UID-A ", want: "835d2c08cec135614912f50428dfdebef0e5a60da10eb375731f002a62118e1b"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := NodeUIDSHA256(test.uid); got != test.want {
				t.Fatalf("NodeUIDSHA256(%q) = %q, want %q", test.uid, got, test.want)
			}
		})
	}
}

func TestNodeUIDSHA256RejectsInvalidInputAndDoesNotNormalize(t *testing.T) {
	t.Parallel()
	for _, uid := range []string{"", string([]byte{0xff}), strings.Repeat("x", maximumNodeUIDBytes+1)} {
		if got := NodeUIDSHA256(uid); got != "" {
			t.Fatalf("invalid UID produced digest %q", got)
		}
	}
	if NodeUIDSHA256("node-uid") == NodeUIDSHA256(" node-uid ") || NodeUIDSHA256("node-uid") == NodeUIDSHA256("Node-UID") {
		t.Fatal("Node UID hashing normalized exact input bytes")
	}
}
