// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package sourcecheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxTextBytes   = 4 * 1024 * 1024
	maxReviewBytes = 128 * 1024 * 1024
)

func classifyInput(input scanInput) scanInput {
	if input.digest == "" {
		input.digest = sha256Hex(input.data)
	}
	if input.nonTextReason != "" || input.kind == "unavailable" || input.kind == "absent" {
		return input
	}
	if input.kind == "gitlink" {
		input.nonTextReason = "gitlink"
		return input
	}
	if len(input.data) > maxTextBytes {
		input.kind = "non_text"
		input.nonTextReason = "size_limit"
		return input
	}
	if decoded, ok := decodeText(input.data); ok {
		input.data = []byte(decoded)
		if input.kind == "" {
			input.kind = "text"
		}
		return input
	}
	input.kind = "non_text"
	if bytes.IndexByte(input.data, 0) >= 0 {
		input.nonTextReason = "nul_byte"
	} else {
		input.nonTextReason = "invalid_utf8"
	}
	return input
}

func decodeText(data []byte) (string, bool) {
	if utf8.Valid(data) && bytes.IndexByte(data, 0) < 0 {
		return string(data), true
	}
	if len(data) < 4 || len(data)%2 != 0 {
		return "", false
	}
	payload := data
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		order = binary.LittleEndian
		payload = data[2:]
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		order = binary.BigEndian
		payload = data[2:]
	default:
		var ok bool
		order, ok = alternatingNULByteOrder(data)
		if !ok {
			return "", false
		}
	}
	if len(payload) == 0 || len(payload)%2 != 0 {
		return "", false
	}
	units := make([]uint16, len(payload)/2)
	for index := range units {
		units[index] = order.Uint16(payload[index*2 : index*2+2])
	}
	if !validUTF16Units(units) {
		return "", false
	}
	decoded := string(utf16.Decode(units))
	if !plausibleText(decoded) {
		return "", false
	}
	return decoded, true
}

func alternatingNULByteOrder(data []byte) (binary.ByteOrder, bool) {
	pairs := len(data) / 2
	if pairs < 2 {
		return nil, false
	}
	littleNULs := 0
	bigNULs := 0
	for index := 0; index+1 < len(data); index += 2 {
		if data[index+1] == 0 {
			littleNULs++
		}
		if data[index] == 0 {
			bigNULs++
		}
	}
	minimum := (pairs*3 + 4) / 5
	if littleNULs >= minimum && littleNULs > bigNULs {
		return binary.LittleEndian, true
	}
	if bigNULs >= minimum && bigNULs > littleNULs {
		return binary.BigEndian, true
	}
	return nil, false
}

func validUTF16Units(units []uint16) bool {
	for index := 0; index < len(units); index++ {
		unit := units[index]
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if index+1 >= len(units) || units[index+1] < 0xdc00 || units[index+1] > 0xdfff {
				return false
			}
			index++
		case unit >= 0xdc00 && unit <= 0xdfff:
			return false
		}
	}
	return true
}

func plausibleText(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == 0 || character == unicode.ReplacementChar {
			return false
		}
		if character == '\n' || character == '\r' || character == '\t' {
			continue
		}
		if !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
