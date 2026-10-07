// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package etcdrecovery

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type filePolicy int

const (
	exactOwnerOnly filePolicy = iota
	currentOrRootReadOnly
	trustedExecutable
)

type protectedFile struct {
	path    string
	file    *os.File
	initial os.FileInfo
	maximum int64
	policy  filePolicy
}

func readProtectedBytes(path string, maximum int64) ([]byte, error) {
	return readProtectedBytesContext(context.Background(), path, maximum)
}

func readProtectedBytesContext(ctx context.Context, path string, maximum int64) ([]byte, error) {
	opened, err := openProtectedFile(path, maximum, exactOwnerOnly)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	data := make([]byte, opened.initial.Size())
	if _, err := io.ReadFull(&protectedContextReader{ctx: ctx, reader: opened.file}, data); err != nil ||
		len(data) == 0 || int64(len(data)) > maximum || opened.ValidateStable() != nil {
		clear(data)
		return nil, errors.New("read protected input")
	}
	return data, nil
}

type protectedContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *protectedContextReader) Read(data []byte) (int, error) {
	if reader == nil || reader.ctx == nil || reader.reader == nil {
		return 0, errors.New("context reader is invalid")
	}
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

func openProtectedFile(path string, maximum int64, policy filePolicy) (*protectedFile, error) {
	clean := filepath.Clean(path)
	if maximum < 1 || !filepath.IsAbs(clean) || clean != path || clean == string(filepath.Separator) {
		return nil, errors.New("protected input path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil || resolved != clean {
		return nil, errors.New("protected input path contains a link")
	}
	parentInfo, err := os.Lstat(filepath.Dir(clean))
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o002 != 0 {
		return nil, errors.New("protected input directory is invalid")
	}
	selected, err := os.Lstat(clean)
	if err != nil || !validProtectedInfo(selected, maximum, policy) {
		return nil, errors.New("protected input identity is invalid")
	}
	// #nosec G304 -- clean is an absolute, symlink-free operator mount path;
	// O_NOFOLLOW plus the before/after inode checks pin the final component.
	file, err := os.OpenFile(clean, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("open protected input")
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(selected, opened) || !sameFileMetadata(selected, opened) || !validProtectedInfo(opened, maximum, policy) {
		_ = file.Close()
		return nil, errors.New("protected input changed while opening")
	}
	return &protectedFile{clean, file, opened, maximum, policy}, nil
}

func (input *protectedFile) Digest() (string, int64, error) {
	return input.DigestContext(context.Background())
}

func (input *protectedFile) DigestContext(ctx context.Context) (string, int64, error) {
	if input == nil || input.file == nil {
		return "", 0, errors.New("protected input is closed")
	}
	if _, err := input.file.Seek(0, io.SeekStart); err != nil {
		return "", 0, errors.New("seek protected input")
	}
	digest, count, err := hashReaderContext(ctx, io.LimitReader(input.file, input.maximum+1))
	if err != nil || count != input.initial.Size() || count > input.maximum || input.ValidateStable() != nil {
		return "", count, errors.New("digest protected input")
	}
	if _, err := input.file.Seek(0, io.SeekStart); err != nil {
		return "", count, errors.New("rewind protected input")
	}
	return digest, count, nil
}

func copyProtectedFileContext(ctx context.Context, input *protectedFile, destination, expectedSHA256 string, expectedBytes int64) (*protectedFile, error) {
	clean := filepath.Clean(destination)
	if ctx == nil || input == nil || input.file == nil || ctx.Err() != nil ||
		!filepath.IsAbs(clean) || clean != destination || !validSHA256(expectedSHA256) ||
		expectedBytes <= 0 || expectedBytes > input.maximum || expectedBytes != input.initial.Size() {
		return nil, errors.New("protected copy input is invalid")
	}
	if _, err := input.file.Seek(0, io.SeekStart); err != nil {
		return nil, errors.New("rewind protected copy input")
	}
	// #nosec G304 -- destination is a fixed name under the fresh owner-only
	// workspace; O_EXCL and O_NOFOLLOW prevent replacement or link traversal.
	output, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("create protected copy")
	}
	complete := false
	defer func() {
		if !complete {
			_ = output.Close()
			_ = os.Remove(clean)
		}
	}()
	buffer := make([]byte, 128<<10)
	written, copyErr := io.CopyBuffer(
		output,
		&protectedContextReader{ctx: ctx, reader: io.LimitReader(input.file, expectedBytes+1)},
		buffer,
	)
	clear(buffer)
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != expectedBytes ||
		input.ValidateStable() != nil {
		return nil, errors.New("copy protected input")
	}
	if _, err := input.file.Seek(0, io.SeekStart); err != nil {
		return nil, errors.New("rewind protected input after copy")
	}
	copied, err := openProtectedFile(clean, input.maximum, exactOwnerOnly)
	if err != nil {
		return nil, errors.New("open protected copy")
	}
	digest, count, err := copied.DigestContext(ctx)
	if err != nil || digest != expectedSHA256 || count != expectedBytes {
		_ = copied.Close()
		return nil, errors.New("protected copy identity is invalid")
	}
	complete = true
	return copied, nil
}

func (input *protectedFile) ValidateStable() error {
	if input == nil || input.file == nil {
		return errors.New("protected input is closed")
	}
	descriptor, descriptorErr := input.file.Stat()
	selected, pathErr := os.Lstat(input.path)
	if descriptorErr != nil || pathErr != nil || !os.SameFile(input.initial, descriptor) || !os.SameFile(descriptor, selected) ||
		!sameFileMetadata(input.initial, descriptor) || !sameFileMetadata(descriptor, selected) ||
		!validProtectedInfo(descriptor, input.maximum, input.policy) || !validProtectedInfo(selected, input.maximum, input.policy) {
		return errors.New("protected input changed")
	}
	return nil
}

func (input *protectedFile) ValidateIdentity() error {
	if input == nil || input.file == nil {
		return errors.New("protected input is closed")
	}
	descriptor, descriptorErr := input.file.Stat()
	selected, pathErr := os.Lstat(input.path)
	if descriptorErr != nil || pathErr != nil || !os.SameFile(input.initial, descriptor) ||
		!os.SameFile(descriptor, selected) ||
		!validProtectedInfo(descriptor, input.maximum, input.policy) ||
		!validProtectedInfo(selected, input.maximum, input.policy) {
		return errors.New("protected input identity changed")
	}
	return nil
}

func discardProtectedFile(input *protectedFile) error {
	if input == nil || input.file == nil || input.ValidateIdentity() != nil {
		return errors.New("disposable protected input identity is invalid")
	}
	path := input.path
	if err := input.Close(); err != nil {
		return errors.New("close disposable protected input")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("remove disposable protected input")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("disposable protected input still exists")
	}
	return nil
}

func (input *protectedFile) Close() error {
	if input == nil || input.file == nil {
		return nil
	}
	err := input.file.Close()
	input.file = nil
	return err
}

func validProtectedInfo(info os.FileInfo, maximum int64, policy filePolicy) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return false
	}
	owner := int64(stat.Uid)
	effective := int64(os.Geteuid())
	permissions := info.Mode().Perm()
	switch policy {
	case exactOwnerOnly:
		return owner == effective && (permissions == 0o400 || permissions == 0o600)
	case currentOrRootReadOnly:
		return (owner == effective || owner == 0) && permissions&0o022 == 0
	case trustedExecutable:
		return (owner == effective || owner == 0) && permissions&0o022 == 0 && permissions&0o111 != 0
	default:
		return false
	}
}

func sameFileMetadata(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Mode() == right.Mode() &&
		left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}
