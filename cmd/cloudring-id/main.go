// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/privateartifact"
	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/iam"
	"github.com/opencloudtech/CloudRING/pkg/identity"
)

const (
	defaultVerifyTokenLifetime = 24 * time.Hour
	maxJWKSBytes               = 8 << 20
	maxCompactJWTBytes         = 64 << 10
)

type contractEvidence struct {
	Status                             string   `json:"status"`
	ReadinessClaimed                   bool     `json:"readinessClaimed"`
	SyntheticOnly                      bool     `json:"syntheticOnly"`
	DiscoveryValidated                 bool     `json:"discoveryValidated"`
	JWKSKeyCount                       int      `json:"jwksKeyCount"`
	ManagementPanelHiddenUntilIamAllow bool     `json:"managementPanelHiddenUntilIamAllow"`
	ForbiddenAlgorithmsRejected        bool     `json:"forbiddenAlgorithmsRejected"`
	CSRFRequiredForBrowserWrites       bool     `json:"csrfRequiredForBrowserWrites"`
	BootstrapAdminExternalSecretOnly   bool     `json:"bootstrapAdminExternalSecretOnly"`
	Notes                              []string `json:"notes"`
}

type tokenEvidence struct {
	Status            string           `json:"status"`
	IssuerValidated   bool             `json:"issuerValidated"`
	AudienceValidated bool             `json:"audienceValidated"`
	SubjectPresent    bool             `json:"subjectPresent,omitempty"`
	GroupCount        int              `json:"groupCount,omitempty"`
	NamespaceCount    int              `json:"namespaceCount,omitempty"`
	ExpiresAt         string           `json:"expiresAt,omitempty"`
	Denial            *iam.DeniedState `json:"denial,omitempty"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "contract":
		return runContract(args[1:])
	case "verify-token":
		return runVerifyToken(args[1:])
	default:
		return usageError()
	}
}

func runContract(args []string) error {
	fs := flag.NewFlagSet("cloudring-id contract", flag.ContinueOnError)
	issuer := fs.String("issuer", "https://id.cloudring.example", "OIDC issuer URL")
	audience := fs.String("audience", "cloudring-console", "expected JWT audience")
	evidencePath := fs.String("evidence", "", "optional JSON evidence path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	now := time.Now().UTC()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	runtime, err := identity.NewRuntime(identity.RuntimeConfig{
		Issuer:                *issuer,
		AuthorizationEndpoint: strings.TrimRight(*issuer, "/") + "/oauth2/authorize",
		TokenEndpoint:         strings.TrimRight(*issuer, "/") + "/oauth2/token",
		JWKSURI:               strings.TrimRight(*issuer, "/") + "/oauth2/jwks",
		Audience:              *audience,
		AuthorizedParty:       *audience,
		ExpectedJOSEType:      "JWT",
		JWTClassClaim:         "token_use",
		ExpectedJWTClass:      "id",
		AllowedAlgorithms:     []string{"RS256", "ES256"},
		RequiredClaims:        []string{"iss", "aud", "azp", "exp", "iat", "sub", "token_use", "groups", "platform_namespaces"},
		GroupsClaim:           "groups",
		NamespacesClaim:       "platform_namespaces",
		TokenMaxLifetime:      time.Hour,
		ClockSkew:             time.Minute,
		JWKSCacheTTL:          5 * time.Minute,
		RotationOverlap:       25 * time.Hour,
		Keys: []identity.SigningKey{{
			KeyID:      "runtime-contract-rs256",
			Algorithm:  "RS256",
			PublicKey:  &key.PublicKey,
			ActiveFrom: now.Add(-time.Minute),
		}},
	})
	if err != nil {
		return err
	}
	discovery := runtime.Discovery()
	if err := runtime.ValidateOIDCDiscovery(discovery); err != nil {
		return err
	}
	if err := runtime.ValidateCloudRINGDiscoveryPolicy(discovery); err != nil {
		return err
	}
	report := contractEvidence{
		Status:                             "contract-valid",
		ReadinessClaimed:                   false,
		SyntheticOnly:                      true,
		DiscoveryValidated:                 true,
		JWKSKeyCount:                       len(runtime.JWKS(now).Keys),
		ManagementPanelHiddenUntilIamAllow: !identity.ManagementPanelAllowed(identity.ManagementDecision{Authenticated: true, TokenValid: true, IAMAllow: false}),
		ForbiddenAlgorithmsRejected:        !contains(discovery.IDTokenSigningAlgValuesSupported, "HS256") && !contains(discovery.IDTokenSigningAlgValuesSupported, "none"),
		CSRFRequiredForBrowserWrites:       discovery.CloudRINGBrowserWriteCSRFRequirement == "required",
		BootstrapAdminExternalSecretOnly:   discovery.CloudRINGBootstrapAdminSecretPolicy == "exactly-one-admin-env-or-external-secret-references-only",
		Notes: []string{
			"synthetic in-process contract validation only; no installation was contacted",
			"does not claim identity-provider, session-store, recovery-code, or live IAM readiness",
			"runtime contract uses asymmetric JWT algorithms only",
			"bootstrap credential fields are references, not plaintext material",
			"management panel remains hidden until IAM allow",
		},
	}
	if *evidencePath != "" {
		if err := writeJSON(*evidencePath, report); err != nil {
			return err
		}
	}
	fmt.Printf("CLOUDRING_ID_CONTRACT_JSON:%s\n", mustJSON(report))
	fmt.Println("cloudring_id_contract_valid")
	return nil
}

func runVerifyToken(args []string) error {
	fs := flag.NewFlagSet("cloudring-id verify-token", flag.ContinueOnError)
	issuer := fs.String("issuer", "", "expected OIDC issuer URL")
	audience := fs.String("audience", "", "expected JWT audience")
	jwksPath := fs.String("jwks", "", "JWKS JSON file")
	tokenPath := fs.String("token-file", "", "compact JWT file")
	evidencePath := fs.String("evidence", "", "optional JSON evidence path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *issuer == "" || *audience == "" || *jwksPath == "" || *tokenPath == "" {
		return usageError()
	}
	now := time.Now().UTC()
	runtime, err := runtimeFromJWKS(*issuer, *audience, *jwksPath)
	if err != nil {
		return err
	}
	token, err := readOperatorFile(*tokenPath, maxCompactJWTBytes, true)
	if err != nil {
		return fmt.Errorf("read token file: %w", err)
	}
	claims, err := runtime.VerifyJWT(strings.TrimSpace(string(token)), now)
	if err != nil {
		denial := iam.TokenRejectedDeniedState()
		report := tokenEvidence{Status: "denied", Denial: &denial}
		if *evidencePath != "" {
			if writeErr := writeJSON(*evidencePath, report); writeErr != nil {
				return writeErr
			}
		}
		fmt.Printf("CLOUDRING_ID_TOKEN_JSON:%s\n", mustJSON(report))
		fmt.Println("cloudring_id_token_denied")
		return fmt.Errorf("%s: %w", denial.Code, err)
	}
	report := tokenEvidence{
		Status:            "allowed",
		IssuerValidated:   claims.Issuer == *issuer,
		AudienceValidated: contains(claims.Audience, *audience),
		SubjectPresent:    claims.Subject != "",
		GroupCount:        len(claims.Groups),
		NamespaceCount:    len(claims.Namespaces),
		ExpiresAt:         claims.ExpiresAt.Format(time.RFC3339),
	}
	if *evidencePath != "" {
		if err := writeJSON(*evidencePath, report); err != nil {
			return err
		}
	}
	fmt.Printf("CLOUDRING_ID_TOKEN_JSON:%s\n", mustJSON(report))
	fmt.Println("cloudring_id_token_verified")
	return nil
}

func runtimeFromJWKS(issuer, audience, jwksPath string) (*identity.Runtime, error) {
	data, err := readOperatorFile(jwksPath, maxJWKSBytes, false)
	if err != nil {
		return nil, fmt.Errorf("read jwks: %w", err)
	}
	var jwks identity.JWKS
	if err := strictjson.Decode(data, &jwks); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	keys, err := identity.SigningKeysFromJWKS(jwks)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(issuer, "/")
	return identity.NewRuntime(identity.RuntimeConfig{
		Issuer:                issuer,
		AuthorizationEndpoint: base + "/oauth2/authorize",
		TokenEndpoint:         base + "/oauth2/token",
		JWKSURI:               base + "/oauth2/jwks",
		Audience:              audience,
		AuthorizedParty:       audience,
		ExpectedJOSEType:      "JWT",
		JWTClassClaim:         "token_use",
		ExpectedJWTClass:      "id",
		AllowedAlgorithms:     []string{"RS256", "ES256"},
		RequiredClaims:        []string{"iss", "aud", "azp", "exp", "iat", "sub", "token_use", "groups", "platform_namespaces"},
		GroupsClaim:           "groups",
		NamespacesClaim:       "platform_namespaces",
		TokenMaxLifetime:      defaultVerifyTokenLifetime,
		ClockSkew:             time.Minute,
		JWKSCacheTTL:          5 * time.Minute,
		RotationOverlap:       25 * time.Hour,
		Keys:                  keys,
	})
}

func usageError() error {
	return errors.New("usage: cloudring-id contract --issuer https://... --audience cloudring-console [--evidence path] OR cloudring-id verify-token --issuer https://... --audience cloudring-console --jwks jwks.json --token-file token.jwt [--evidence path]")
}

func writeJSON(path string, value any) error {
	return privateartifact.WriteNewJSON(path, value)
}

func readOperatorFile(path string, maximum int64, ownerOnly bool) ([]byte, error) {
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return nil, errors.New("operator input path is invalid")
	}
	file, err := openProtectedOperatorFile(clean, ownerOnly)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("operator input exceeds size limit")
	}
	return data, nil
}

func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(data)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
