// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package sourcecheck

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestClassifyInput_distinguishes_binary_and_utf16_text(t *testing.T) {
	binaryInput := classifyInput(scanInput{path: "artifact.bin", variant: "worktree", data: []byte{0x00, 0xff, 0x00, 0x81}})
	if binaryInput.nonTextReason == "" || binaryInput.kind != "non_text" {
		t.Fatalf("binary input was not classified as non-text: %+v", binaryInput)
	}

	text := "safe Windows text"
	units := utf16.Encode([]rune(text))
	data := []byte{0xff, 0xfe}
	for _, unit := range units {
		encoded := make([]byte, 2)
		binary.LittleEndian.PutUint16(encoded, unit)
		data = append(data, encoded...)
	}
	textInput := classifyInput(scanInput{path: "notes.txt", variant: "worktree", data: data})
	if textInput.nonTextReason != "" || string(textInput.data) != text {
		t.Fatalf("UTF-16 text was not decoded: %+v", textInput)
	}
}

func TestNonTextAllowed_requires_exact_path_and_digest(t *testing.T) {
	input := classifyInput(scanInput{path: "assets/image.bin", variant: "worktree", data: []byte{0x00, 0xff, 0x01}})
	allowances, err := prepareAllowances([]NonTextAllowance{{Path: "assets/image.bin", SHA256: input.digest}})
	if err != nil {
		t.Fatalf("prepare allowance: %v", err)
	}
	if !consumeAllowance(allowances, input.path, input.digest) {
		t.Fatal("expected exact reviewed non-text artifact to be allowed")
	}
	if consumeAllowance(allowances, "assets/other.bin", input.digest) || consumeAllowance(allowances, input.path, stringsOf("0", 64)) {
		t.Fatal("non-text allowance accepted a mismatched path or digest")
	}
}

func stringsOf(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}
