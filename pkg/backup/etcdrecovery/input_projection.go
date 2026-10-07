// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package etcdrecovery

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

var (
	kubernetesDNSLabelPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	kubernetesDNSSubdomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// CanonicalInputSecretProjection returns the exact canonical document whose
// SHA-256 is carried by Request.InputSecretSHA256.
func CanonicalInputSecretProjection(projection InputSecretProjection) ([]byte, error) {
	if projection.SchemaVersion != InputProjectionSchemaVersion ||
		!kubernetesDNSLabelPattern.MatchString(projection.Namespace) ||
		!validKubernetesDNSSubdomain(projection.ProjectedObjectName) ||
		projection.SecretKey != "request.json" ||
		projection.MountPath != DefaultRequestPath ||
		projection.DefaultMode != 0o440 ||
		projection.Optional || !projection.ReadOnly {
		return nil, errors.New("recovery input Secret projection is invalid")
	}
	payload, err := json.Marshal(projection)
	if err != nil {
		return nil, errors.New("encode recovery input Secret projection")
	}
	return payload, nil
}

func validKubernetesDNSSubdomain(value string) bool {
	if !kubernetesDNSSubdomainPattern.MatchString(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !kubernetesDNSLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// InputSecretProjectionSHA256 returns the binding used by
// Request.InputSecretSHA256.
func InputSecretProjectionSHA256(projection InputSecretProjection) (string, error) {
	payload, err := CanonicalInputSecretProjection(projection)
	if err != nil {
		return "", err
	}
	defer clear(payload)
	return digestBytes(payload), nil
}
