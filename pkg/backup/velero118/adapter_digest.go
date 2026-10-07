// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package velero118

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
)

const AdapterRequestCanonicalization = "cloudring.restore-proof.adapter-canonical-json/v1"

// CanonicalAdapterRequestJSON returns the language-neutral byte representation
// whose SHA-256 is carried in adapter responses. The representation is UTF-8
// JSON with lexicographically sorted object keys, no insignificant whitespace,
// and the string escaping rules published with the adapter protocol.
func CanonicalAdapterRequestJSON(request any) ([]byte, error) {
	switch request.(type) {
	case ProbeRequest, *ProbeRequest, BackendRequest, *BackendRequest:
	default:
		return nil, errors.New("unsupported restore-proof adapter request")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, errors.New("encode restore-proof adapter request")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || decoder.More() {
		return nil, errors.New("decode restore-proof adapter request")
	}
	canonical := make([]byte, 0, len(payload))
	canonical, err = appendCanonicalAdapterJSON(canonical, value)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

// AdapterRequestSHA256 returns the canonical adapter request digest. It never
// hashes Go's struct field order or the wire encoder's whitespace choices.
func AdapterRequestSHA256(request any) string {
	payload, err := CanonicalAdapterRequestJSON(request)
	if err != nil {
		return ""
	}
	return restoreproof.SHA256(string(payload))
}

func appendCanonicalAdapterJSON(destination []byte, value any) ([]byte, error) {
	switch typed := value.(type) {
	case nil:
		return append(destination, "null"...), nil
	case bool:
		return strconv.AppendBool(destination, typed), nil
	case string:
		return appendCanonicalAdapterString(destination, typed)
	case json.Number:
		return nil, errors.New("numeric adapter request fields are not supported by canonical-json/v1")
	case []any:
		destination = append(destination, '[')
		for index, item := range typed {
			if index != 0 {
				destination = append(destination, ',')
			}
			var err error
			destination, err = appendCanonicalAdapterJSON(destination, item)
			if err != nil {
				return nil, err
			}
		}
		return append(destination, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		destination = append(destination, '{')
		for index, key := range keys {
			if index != 0 {
				destination = append(destination, ',')
			}
			var err error
			destination, err = appendCanonicalAdapterString(destination, key)
			if err != nil {
				return nil, err
			}
			destination = append(destination, ':')
			destination, err = appendCanonicalAdapterJSON(destination, typed[key])
			if err != nil {
				return nil, err
			}
		}
		return append(destination, '}'), nil
	default:
		return nil, errors.New("unsupported canonical adapter JSON value")
	}
}

func appendCanonicalAdapterString(destination []byte, value string) ([]byte, error) {
	if !utf8.ValidString(value) {
		return nil, errors.New("adapter request contains invalid UTF-8")
	}
	destination = append(destination, '"')
	const hexadecimal = "0123456789abcdef"
	for _, character := range value {
		switch character {
		case '"', '\\':
			destination = append(destination, '\\', byte(character))
		case '\b':
			destination = append(destination, `\b`...)
		case '\t':
			destination = append(destination, `\t`...)
		case '\n':
			destination = append(destination, `\n`...)
		case '\f':
			destination = append(destination, `\f`...)
		case '\r':
			destination = append(destination, `\r`...)
		default:
			if character < 0x20 {
				destination = append(destination, '\\', 'u', '0', '0', hexadecimal[character>>4], hexadecimal[character&0x0f])
			} else {
				destination = utf8.AppendRune(destination, character)
			}
		}
	}
	return append(destination, '"'), nil
}
