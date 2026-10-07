// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package etcdrecovery

import (
	"context"
	"errors"
)

type filePolicy int

const (
	exactOwnerOnly filePolicy = iota
	currentOrRootReadOnly
	trustedExecutable
)

type protectedFile struct{}

func readProtectedBytes(string, int64) ([]byte, error) {
	return nil, errors.New("protected recovery inputs are unsupported")
}
func readProtectedBytesContext(context.Context, string, int64) ([]byte, error) {
	return nil, errors.New("protected recovery inputs are unsupported")
}
func openProtectedFile(string, int64, filePolicy) (*protectedFile, error) {
	return nil, errors.New("protected recovery inputs are unsupported")
}
func (*protectedFile) Digest() (string, int64, error) { return "", 0, errors.New("unsupported") }
func (*protectedFile) DigestContext(context.Context) (string, int64, error) {
	return "", 0, errors.New("unsupported")
}
func copyProtectedFileContext(context.Context, *protectedFile, string, string, int64) (*protectedFile, error) {
	return nil, errors.New("unsupported")
}
func (*protectedFile) ValidateStable() error { return errors.New("unsupported") }
func (*protectedFile) ValidateIdentity() error {
	return errors.New("unsupported")
}
func discardProtectedFile(*protectedFile) error { return errors.New("unsupported") }
func (*protectedFile) Close() error             { return nil }
