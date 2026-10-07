// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package identity

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"strings"
	"time"
)

type SameSiteMode string

const (
	SameSiteLax    SameSiteMode = "Lax"
	SameSiteStrict SameSiteMode = "Strict"
)

type CookiePolicy struct {
	Name     string
	Value    string
	Path     string
	Lifetime time.Duration
	SameSite SameSiteMode
}

func NewSessionCookie(policy CookiePolicy, now time.Time) (*http.Cookie, error) {
	sameSite, err := validateHostCookiePolicy(policy.Name, policy.Value, policy.Path, policy.SameSite, true)
	if err != nil {
		return nil, err
	}
	if policy.Lifetime < time.Second || policy.Lifetime > 24*time.Hour {
		return nil, errors.New("cookie lifetime must be positive and bounded")
	}
	return newSecureHostCookie(
		policy.Name,
		policy.Value,
		policy.Path,
		now.Add(policy.Lifetime),
		int(policy.Lifetime/time.Second),
		sameSite,
	), nil
}

func ExpireSessionCookie(policy CookiePolicy, now time.Time) (*http.Cookie, error) {
	sameSite, err := validateHostCookiePolicy(policy.Name, "", policy.Path, policy.SameSite, false)
	if err != nil {
		return nil, err
	}
	return newSecureHostCookie(policy.Name, "", policy.Path, now.Add(-time.Hour), -1, sameSite), nil
}

func newSecureHostCookie(name, value, path string, expires time.Time, maxAge int, sameSite http.SameSite) *http.Cookie {
	// Lax is the secure baseline for OIDC state and nonce cookies: it permits
	// them on the provider's top-level callback redirect while excluding
	// cross-site subrequests. A validated Strict policy may narrow this further.
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		Expires:  expires,
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if sameSite == http.SameSiteStrictMode {
		cookie.SameSite = http.SameSiteStrictMode
	}
	return cookie
}

func validateHostCookiePolicy(name, value, path string, sameSitePolicy SameSiteMode, requireValue bool) (http.SameSite, error) {
	if !strings.HasPrefix(name, "__Host-") {
		return 0, errors.New("session cookie name must use the __Host- prefix")
	}
	if path != "/" {
		return 0, errors.New("__Host- session cookie path must be /")
	}
	if requireValue && value == "" {
		return 0, errors.New("cookie value is required")
	}
	candidate := newSecureHostCookie(name, value, path, time.Time{}, 0, http.SameSiteLaxMode)
	if err := candidate.Valid(); err != nil {
		return 0, errors.New("cookie name or value is invalid")
	}
	switch sameSitePolicy {
	case SameSiteStrict:
		return http.SameSiteStrictMode, nil
	case SameSiteLax, "":
		return http.SameSiteLaxMode, nil
	default:
		return 0, errors.New("cookie SameSite must be Lax or Strict")
	}
}

type CSRFManager struct {
	keyMaterial []byte
	maxAge      time.Duration
}

const minCSRFKeyMaterialBytes = 32
const maxEncodedCSRFTokenBytes = 128

func NewCSRFManager(keyMaterial []byte, maxAge time.Duration) CSRFManager {
	keyCopy := append([]byte(nil), keyMaterial...)
	return CSRFManager{keyMaterial: keyCopy, maxAge: maxAge}
}

func (manager CSRFManager) Issue(sessionID string, now time.Time) (string, error) {
	if len(manager.keyMaterial) < minCSRFKeyMaterialBytes {
		return "", errors.New("csrf key material must be at least 32 bytes")
	}
	if sessionID == "" {
		return "", errors.New("session id is required")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	var timestamp bytes.Buffer
	if err := binary.Write(&timestamp, binary.BigEndian, now.Unix()); err != nil {
		return "", errors.New("encode csrf token timestamp")
	}
	message := append(append([]byte{}, nonce...), timestamp.Bytes()...)
	mac := manager.csrfMAC(sessionID, message)
	raw := append(message, mac...)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (manager CSRFManager) Check(csrfValue, sessionID string, now time.Time) error {
	if len(manager.keyMaterial) < minCSRFKeyMaterialBytes {
		return errors.New("csrf key material must be at least 32 bytes")
	}
	if csrfValue == "" {
		return errors.New("csrf token is required")
	}
	if len(csrfValue) > maxEncodedCSRFTokenBytes {
		return errors.New("csrf token is malformed")
	}
	if sessionID == "" {
		return errors.New("session id is required")
	}
	raw, err := base64.RawURLEncoding.DecodeString(csrfValue)
	if err != nil {
		return errors.New("csrf token is malformed")
	}
	if len(raw) != 16+8+sha256.Size {
		return errors.New("csrf token length is invalid")
	}
	message := raw[:24]
	wantMAC := manager.csrfMAC(sessionID, message)
	gotMAC := raw[24:]
	if subtle.ConstantTimeCompare(wantMAC, gotMAC) != 1 {
		return errors.New("csrf token signature is invalid")
	}
	var issuedAtUnix int64
	if err := binary.Read(bytes.NewReader(message[16:24]), binary.BigEndian, &issuedAtUnix); err != nil {
		return errors.New("csrf token timestamp is invalid")
	}
	issuedAt := time.Unix(issuedAtUnix, 0).UTC()
	if manager.maxAge <= 0 || now.Before(issuedAt) || now.Sub(issuedAt) > manager.maxAge {
		return errors.New("csrf token is expired")
	}
	return nil
}

func (manager CSRFManager) csrfMAC(sessionID string, message []byte) []byte {
	mac := hmac.New(sha256.New, manager.keyMaterial)
	mac.Write([]byte(sessionID))
	mac.Write([]byte{0})
	mac.Write(message)
	return mac.Sum(nil)
}
