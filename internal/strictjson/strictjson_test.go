// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package strictjson

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateRejectsDuplicateTrailingAndOversizedJSON(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		data string
		want error
	}{
		{name: "valid", data: `{"value":9007199254740993}`, want: nil},
		{name: "valid-large-exponent", data: `{"value":1e1000000}`, want: nil},
		{name: "duplicate", data: `{"value":1,"value":2}`, want: ErrDuplicate},
		{name: "trailing", data: `{} {}`, want: ErrInvalid},
		{name: "malformed", data: `{`, want: ErrInvalid},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := Validate([]byte(test.data))
			if !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := Read(strings.NewReader(strings.Repeat("x", MaxDocumentBytes+1))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Read() error = %v, want ErrTooLarge", err)
	}
}

func TestDecodeExactRejectsUnknownField(t *testing.T) {
	t.Parallel()
	var destination struct {
		Known string `json:"known"`
	}
	if err := DecodeExact([]byte(`{"known":"value","unknown":true}`), &destination); err == nil {
		t.Fatal("DecodeExact accepted an unknown field")
	}
	if err := DecodeExact([]byte(`{"known":"value"}`), &destination); err != nil {
		t.Fatalf("DecodeExact valid document: %v", err)
	}
}
