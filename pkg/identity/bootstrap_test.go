// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package identity

import "testing"

func TestBootstrapAdminRequiresSingleExternalSecretMaterial(t *testing.T) {
	valid := BootstrapAdmin{
		Username: CredentialRef{Env: "CLOUDRING_BOOTSTRAP_ADMIN_USERNAME"},
		PasswordHashRef: CredentialRef{
			ExternalSecretRef: &SecretKeyRef{Name: "cloudring-bootstrap-admin", Key: "password-hash"},
		},
		RecoveryCodes:         SecretManagerRef{Provider: "external-secret-manager", Reference: "cloudring/bootstrap-admin/recovery-codes"},
		MFARequired:           true,
		RotateAfterFirstLogin: true,
	}
	if err := ValidateBootstrapAdmins([]BootstrapAdmin{valid}); err != nil {
		t.Fatalf("valid bootstrap admin rejected: %v", err)
	}
	if err := ValidateBootstrapAdmins([]BootstrapAdmin{}); err == nil {
		t.Fatal("missing bootstrap admin should fail")
	}
	if err := ValidateBootstrapAdmins([]BootstrapAdmin{valid, valid}); err == nil {
		t.Fatal("multiple bootstrap admins should fail")
	}
	plaintext := valid
	plaintext.PasswordHashRef = CredentialRef{Plaintext: "correct-horse-battery-staple"}
	if err := ValidateBootstrapAdmins([]BootstrapAdmin{plaintext}); err == nil {
		t.Fatal("plaintext password material should fail")
	}
	noMFA := valid
	noMFA.MFARequired = false
	if err := ValidateBootstrapAdmins([]BootstrapAdmin{noMFA}); err == nil {
		t.Fatal("bootstrap admin without MFA should fail")
	}
}
