// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package identity

import (
	"errors"
	"fmt"
	"regexp"
)

type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type CredentialRef struct {
	Env               string        `json:"env,omitempty"`
	ExternalSecretRef *SecretKeyRef `json:"externalSecretRef,omitempty"`
	Plaintext         string        `json:"plaintext,omitempty"`
}

type SecretManagerRef struct {
	Provider  string `json:"provider"`
	Reference string `json:"reference"`
}

type BootstrapAdmin struct {
	Username              CredentialRef      `json:"username"`
	PasswordHashRef       CredentialRef      `json:"passwordHashRef"`
	RecoveryCodes         SecretManagerRef   `json:"recoveryCodes"`
	MFARequired           bool               `json:"mfaRequired"`
	RotateAfterFirstLogin bool               `json:"rotateAfterFirstLogin"`
	AdditionalSecretRefs  []SecretManagerRef `json:"additionalSecretRefs,omitempty"`
}

func ValidateBootstrapAdmins(admins []BootstrapAdmin) error {
	if len(admins) != 1 {
		return fmt.Errorf("expected exactly one bootstrap admin, got %d", len(admins))
	}
	admin := admins[0]
	if err := admin.Username.validate("username"); err != nil {
		return err
	}
	if err := admin.PasswordHashRef.validate("password hash"); err != nil {
		return err
	}
	if admin.RecoveryCodes.Provider == "" || admin.RecoveryCodes.Reference == "" {
		return errors.New("recovery codes must reference an external secret manager")
	}
	if !admin.MFARequired {
		return errors.New("bootstrap admin must be MFA-ready")
	}
	if !admin.RotateAfterFirstLogin {
		return errors.New("bootstrap admin must rotate after first login")
	}
	return nil
}

func (ref CredentialRef) validate(label string) error {
	if ref.Plaintext != "" {
		return fmt.Errorf("%s must not include plaintext credential material", label)
	}
	sources := 0
	if ref.Env != "" {
		sources++
		if !envNamePattern.MatchString(ref.Env) {
			return fmt.Errorf("%s env reference is invalid", label)
		}
	}
	if ref.ExternalSecretRef != nil {
		sources++
		if ref.ExternalSecretRef.Name == "" || ref.ExternalSecretRef.Key == "" {
			return fmt.Errorf("%s external secret reference is incomplete", label)
		}
	}
	if sources != 1 {
		return fmt.Errorf("%s must reference exactly one env or external secret source", label)
	}
	return nil
}

var envNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
