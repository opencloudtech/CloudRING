// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/opencloudtech/CloudRING/internal/privateartifact"
	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/proofsignature"
)

const maxKeyDocumentBytes = 64 << 10

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "key":
		if len(args) < 2 {
			return usageError()
		}
		switch args[1] {
		case "generate":
			return runKeyGenerate(args[2:])
		case "public":
			return runKeyPublic(args[2:])
		default:
			return usageError()
		}
	case "sign":
		return runSign(args[1:])
	case "verify":
		return runVerify(args[1:])
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: cloudring-proof key generate --key-id <id> --secret-output-fd <fd> --trust-policy <path> OR cloudring-proof key public --key-fd <fd> --trust-policy <path> OR cloudring-proof sign --payload <path> --key-fd <fd> --signature <path> OR cloudring-proof verify --payload <path> --signature <path> --trust-policy <path>")
}

func runKeyGenerate(args []string) error {
	fs := flag.NewFlagSet("cloudring-proof key generate", flag.ContinueOnError)
	keyID := fs.String("key-id", "", "source-safe signing key id")
	secretOutputFD := fs.Int("secret-output-fd", -1, "inherited pipe descriptor for the private key document")
	trustPolicyPath := fs.String("trust-policy", "", "new public trust-policy JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *secretOutputFD < 3 || *keyID == "" || *trustPolicyPath == "" {
		return usageError()
	}
	pipe, err := inheritedPipe(*secretOutputFD, "proof-key-output")
	if err != nil {
		return err
	}
	defer pipe.Close()
	key, err := proofsignature.Generate(*keyID)
	if err != nil {
		return err
	}
	defer key.Destroy()
	trustKey, err := key.TrustKey()
	if err != nil {
		return err
	}
	policy, err := proofsignature.NewTrustPolicy(trustKey)
	if err != nil {
		return err
	}
	if err := privateartifact.WriteNewJSON(filepath.Clean(*trustPolicyPath), policy); err != nil {
		return err
	}
	rollbackPolicy := true
	defer func() {
		if rollbackPolicy {
			_ = os.Remove(filepath.Clean(*trustPolicyPath))
		}
	}()
	secret, err := proofsignature.MarshalSigningKey(key)
	if err != nil {
		return err
	}
	defer clear(secret)
	if err := writeAll(pipe, secret); err != nil {
		return errors.New("write proof signing key to protected pipe")
	}
	if err := writeAll(pipe, []byte{'\n'}); err != nil {
		return errors.New("finish proof signing key on protected pipe")
	}
	if err := pipe.Close(); err != nil {
		return errors.New("close proof signing key pipe")
	}
	rollbackPolicy = false
	fmt.Println("cloudring_proof_key_generated")
	return nil
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("cloudring-proof sign", flag.ContinueOnError)
	payloadPath := fs.String("payload", "", "JSON proof payload path")
	keyFD := fs.Int("key-fd", -1, "inherited pipe descriptor containing the private key document")
	signaturePath := fs.String("signature", "", "new detached signature JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *keyFD < 3 || *payloadPath == "" || *signaturePath == "" {
		return usageError()
	}
	payload, err := readCanonicalJSON(*payloadPath)
	if err != nil {
		return errors.New("read canonical proof payload")
	}
	defer clear(payload)
	key, err := readSigningKeyFD(*keyFD)
	if err != nil {
		return err
	}
	defer key.Destroy()
	envelope, err := proofsignature.Sign(payload, key)
	if err != nil {
		return err
	}
	trustKey, err := key.TrustKey()
	if err != nil {
		return err
	}
	if err := proofsignature.Verify(payload, envelope, []proofsignature.TrustKey{trustKey}); err != nil {
		return errors.New("verify newly created proof signature")
	}
	if err := privateartifact.WriteNewJSON(filepath.Clean(*signaturePath), envelope); err != nil {
		return err
	}
	fmt.Println("cloudring_proof_signed")
	return nil
}

func runKeyPublic(args []string) error {
	fs := flag.NewFlagSet("cloudring-proof key public", flag.ContinueOnError)
	keyFD := fs.Int("key-fd", -1, "inherited pipe descriptor containing the private key document")
	trustPolicyPath := fs.String("trust-policy", "", "new public trust-policy JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *keyFD < 3 || *trustPolicyPath == "" {
		return usageError()
	}
	key, err := readSigningKeyFD(*keyFD)
	if err != nil {
		return err
	}
	defer key.Destroy()
	trustKey, err := key.TrustKey()
	if err != nil {
		return err
	}
	policy, err := proofsignature.NewTrustPolicy(trustKey)
	if err != nil {
		return err
	}
	if err := privateartifact.WriteNewJSON(filepath.Clean(*trustPolicyPath), policy); err != nil {
		return err
	}
	fmt.Println("cloudring_proof_public_key_derived")
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("cloudring-proof verify", flag.ContinueOnError)
	payloadPath := fs.String("payload", "", "JSON proof payload path")
	signaturePath := fs.String("signature", "", "detached signature JSON path")
	trustPolicyPath := fs.String("trust-policy", "", "public trust-policy JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *payloadPath == "" || *signaturePath == "" || *trustPolicyPath == "" {
		return usageError()
	}
	payload, err := readCanonicalJSON(*payloadPath)
	if err != nil {
		return errors.New("read canonical proof payload")
	}
	defer clear(payload)
	var envelope proofsignature.Envelope
	if err := readExactJSON(*signaturePath, &envelope); err != nil {
		return errors.New("read proof signature")
	}
	policyData, err := readBoundedFile(*trustPolicyPath, strictjson.MaxDocumentBytes)
	if err != nil {
		return errors.New("read proof trust policy")
	}
	defer clear(policyData)
	policy, err := proofsignature.ParseTrustPolicy(policyData)
	if err != nil {
		return err
	}
	if err := proofsignature.VerifyPolicy(payload, envelope, policy); err != nil {
		return err
	}
	fmt.Println("cloudring_proof_signature_ok")
	return nil
}

func readSigningKeyFD(fd int) (*proofsignature.SigningKey, error) {
	pipe, err := inheritedPipe(fd, "proof-key-input")
	if err != nil {
		return nil, err
	}
	defer pipe.Close()
	data, err := io.ReadAll(io.LimitReader(pipe, maxKeyDocumentBytes+1))
	if err != nil || len(data) > maxKeyDocumentBytes {
		clear(data)
		return nil, errors.New("read proof signing key from protected pipe")
	}
	defer clear(data)
	key, err := proofsignature.ParseSigningKey(data)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func inheritedPipe(fd int, name string) (*os.File, error) {
	if fd < 3 {
		return nil, errors.New("proof key descriptor must be an inherited pipe descriptor of at least 3")
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		return nil, errors.New("open inherited proof key pipe")
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&(os.ModeNamedPipe|os.ModeSocket) == 0 {
		_ = file.Close()
		return nil, errors.New("proof key descriptor must refer to a pipe or socket")
	}
	return file, nil
}

func readCanonicalJSON(path string) ([]byte, error) {
	data, err := readBoundedFile(path, strictjson.MaxDocumentBytes)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var document any
	if err := strictjson.Decode(data, &document); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return nil, errors.New("canonicalize proof payload")
	}
	return canonical, nil
}

func readExactJSON(path string, destination any) error {
	data, err := readBoundedFile(path, strictjson.MaxDocumentBytes)
	if err != nil {
		return err
	}
	defer clear(data)
	if err := strictjson.DecodeExact(data, destination); err != nil {
		return err
	}
	return nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("JSON document is unreadable or oversized")
	}
	return data, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
