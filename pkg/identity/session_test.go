// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSecureCookieAndCSRFValidation(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	cookie, err := NewSessionCookie(CookiePolicy{
		Name:     "__Host-cloudring-session",
		Value:    "opaque-session-id",
		Path:     "/",
		Lifetime: 30 * time.Minute,
		SameSite: SameSiteLax,
	}, now)
	if err != nil {
		t.Fatalf("NewSessionCookie returned error: %v", err)
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.MaxAge <= 0 ||
		cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie missing secure attributes: %#v", cookie)
	}

	csrf := NewCSRFManager([]byte("0123456789abcdef0123456789abcdef"), 10*time.Minute)
	csrfValue, err := csrf.Issue("session-1", now)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if err := csrf.Check(csrfValue, "session-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("valid CSRF token rejected: %v", err)
	}
	if err := csrf.Check("", "session-1", now.Add(time.Minute)); err == nil {
		t.Fatal("browser write without CSRF token should fail")
	}
	if err := csrf.Check(csrfValue, "different-session", now.Add(time.Minute)); err == nil {
		t.Fatal("CSRF token for different session should fail")
	}
}

func TestCSRFRejectsShortKeyMaterial(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	const wantErr = "csrf key material must be at least 32 bytes"

	for name, keyMaterial := range map[string][]byte{
		"empty": nil,
		"short": []byte("short-csrf-key"),
	} {
		t.Run(name, func(t *testing.T) {
			csrf := NewCSRFManager(keyMaterial, 10*time.Minute)
			if csrfValue, err := csrf.Issue("session-1", now); err == nil {
				t.Fatalf("Issue accepted %s CSRF key material and returned %q", name, csrfValue)
			} else if err.Error() != wantErr {
				t.Fatalf("Issue returned %q, want %q", err.Error(), wantErr)
			}

			forgedCSRFValue := csrfTokenSignedForTest(t, csrf, "session-1", now)
			if err := csrf.Check(forgedCSRFValue, "session-1", now.Add(time.Minute)); err == nil {
				t.Fatalf("Check accepted browser-write token signed with %s CSRF key material", name)
			} else if err.Error() != wantErr {
				t.Fatalf("Check returned %q, want %q", err.Error(), wantErr)
			}
		})
	}
}

func TestHostSessionCookieFailsClosedAndExpiresWithSameBoundary(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	base := CookiePolicy{
		Name:     "__Host-cloudring-session",
		Value:    "opaque-session-id",
		Path:     "/",
		Lifetime: time.Minute,
		SameSite: SameSiteStrict,
	}
	tests := []struct {
		name   string
		mutate func(*CookiePolicy)
	}{
		{name: "missing host prefix", mutate: func(value *CookiePolicy) { value.Name = "cloudring-session" }},
		{name: "scoped path", mutate: func(value *CookiePolicy) { value.Path = "/portal" }},
		{name: "invalid value", mutate: func(value *CookiePolicy) { value.Value = "bad\nvalue" }},
		{name: "subsecond lifetime", mutate: func(value *CookiePolicy) { value.Lifetime = time.Millisecond }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			if _, err := NewSessionCookie(candidate, now); err == nil {
				t.Fatalf("NewSessionCookie accepted %s", test.name)
			}
		})
	}

	expired, err := ExpireSessionCookie(base, now)
	if err != nil {
		t.Fatalf("ExpireSessionCookie: %v", err)
	}
	if expired.Name != base.Name || expired.Path != "/" || !expired.Secure || !expired.HttpOnly ||
		expired.SameSite != http.SameSiteStrictMode || expired.MaxAge >= 0 || !expired.Expires.Before(now) {
		t.Fatalf("logout cookie does not preserve the secure boundary: %#v", expired)
	}
}

func TestCSRFFailsClosedOnOversizedFutureAndExpiredValues(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	manager := NewCSRFManager([]byte("0123456789abcdef0123456789abcdef"), 10*time.Minute)
	if err := manager.Check(strings.Repeat("A", maxEncodedCSRFTokenBytes+1), "session-1", now); err == nil {
		t.Fatal("oversized CSRF value was accepted")
	}
	future := csrfTokenSignedForTest(t, manager, "session-1", now.Add(time.Second))
	if err := manager.Check(future, "session-1", now); err == nil {
		t.Fatal("future CSRF value was accepted")
	}
	expired := csrfTokenSignedForTest(t, manager, "session-1", now.Add(-10*time.Minute-time.Second))
	if err := manager.Check(expired, "session-1", now); err == nil {
		t.Fatal("expired CSRF value was accepted")
	}
}

func csrfTokenSignedForTest(t *testing.T, manager CSRFManager, sessionID string, issuedAt time.Time) string {
	t.Helper()
	nonce := []byte("0123456789abcdef")
	var timestamp bytes.Buffer
	if err := binary.Write(&timestamp, binary.BigEndian, issuedAt.Unix()); err != nil {
		t.Fatalf("encode fixture timestamp: %v", err)
	}
	message := append(append([]byte{}, nonce...), timestamp.Bytes()...)
	raw := append(message, manager.csrfMAC(sessionID, message)...)
	return base64.RawURLEncoding.EncodeToString(raw)
}
