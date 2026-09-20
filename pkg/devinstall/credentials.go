// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Credentials are generated once and kept only in the protected installation
// directory and its own guest/Kubernetes Secrets. Never encode this structure
// into a diagnostic report, deterministic plan or command argument.
type Credentials struct {
	OperatorToken               string    `json:"operatorToken"`
	DatabaseAdminPassword       string    `json:"databaseAdminPassword"`
	DatabaseOwnerPassword       string    `json:"databaseOwnerPassword"`
	DatabaseApplicationPassword string    `json:"databaseApplicationPassword"`
	CACertificate               string    `json:"caCertificate"`
	APIKey                      string    `json:"apiKey"`
	APICertificate              string    `json:"apiCertificate"`
	DatabaseKey                 string    `json:"databaseKey"`
	DatabaseCertificate         string    `json:"databaseCertificate"`
	SSHClientPrivateKey         string    `json:"sshClientPrivateKey"`
	SSHClientPublicKey          string    `json:"sshClientPublicKey"`
	SSHHostPrivateKey           string    `json:"sshHostPrivateKey"`
	SSHHostPublicKey            string    `json:"sshHostPublicKey"`
	CertificateExpiresAt        time.Time `json:"certificateExpiresAt"`
}

func randomHex() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate development installation entropy")
	}
	defer clear(value)
	return hex.EncodeToString(value), nil
}

func newCredentials(profile Profile, now time.Time) (Credentials, error) {
	var credentials Credentials
	for _, destination := range []*string{&credentials.OperatorToken, &credentials.DatabaseAdminPassword,
		&credentials.DatabaseOwnerPassword, &credentials.DatabaseApplicationPassword} {
		value, err := randomHex()
		if err != nil {
			return Credentials{}, err
		}
		*destination = value
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Credentials{}, errors.New("generate development certificate authority")
	}
	serial, err := certificateSerial()
	if err != nil {
		return Credentials{}, err
	}
	ca := &x509.Certificate{SerialNumber: serial,
		Subject:   pkix.Name{CommonName: "CloudRING development " + profile.InstallationID},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(30 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return Credentials{}, errors.New("create development certificate authority")
	}
	credentials.CACertificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	credentials.CertificateExpiresAt = now.Add(7 * 24 * time.Hour).UTC()
	credentials.APICertificate, credentials.APIKey, err = leafCertificate(ca, caKey, now,
		credentials.CertificateExpiresAt, []string{apiHostname(profile)}, nil)
	if err != nil {
		return Credentials{}, err
	}
	credentials.DatabaseCertificate, credentials.DatabaseKey, err = leafCertificate(ca, caKey, now,
		credentials.CertificateExpiresAt, []string{"postgresql", "postgresql.cloudring-system", "postgresql.cloudring-system.svc", "postgresql.cloudring-system.svc.cluster.local"}, nil)
	if err != nil {
		return Credentials{}, err
	}
	credentials.SSHClientPrivateKey, credentials.SSHClientPublicKey, err = sshKeyPair()
	if err != nil {
		return Credentials{}, err
	}
	credentials.SSHHostPrivateKey, credentials.SSHHostPublicKey, err = sshKeyPair()
	if err != nil {
		return Credentials{}, err
	}
	return credentials, nil
}

func certificateSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil || serial.Sign() == 0 {
		return nil, errors.New("generate development certificate serial")
	}
	return serial, nil
}

func leafCertificate(ca *x509.Certificate, caKey *ecdsa.PrivateKey, now, expiry time.Time, names []string, addresses []net.IP) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", errors.New("generate development TLS key")
	}
	serial, err := certificateSerial()
	if err != nil {
		return "", "", err
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: expiry, DNSNames: names, IPAddresses: addresses,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, ca, &key.PublicKey, caKey)
	if err != nil {
		return "", "", errors.New("create development TLS certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", errors.New("encode development TLS key")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), nil
}

// Both keys use native Ed25519/OpenSSH formats. The guest has an independent
// random host key, so a valid substrate TLS session cannot substitute a guest.
func sshKeyPair() (string, string, error) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", errors.New("generate installation SSH identity")
	}
	defer clear(key)
	private, err := ssh.MarshalPrivateKey(key, "cloudring-development")
	if err != nil {
		return "", "", errors.New("encode installation SSH identity")
	}
	publicKey, err := ssh.NewPublicKey(public)
	if err != nil {
		return "", "", errors.New("encode installation SSH public key")
	}
	return string(pem.EncodeToMemory(private)), string(ssh.MarshalAuthorizedKey(publicKey)), nil
}
