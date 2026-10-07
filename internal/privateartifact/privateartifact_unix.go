// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package privateartifact

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func privateDirectoryMode(mode os.FileMode) bool {
	return mode.Perm()&0o022 == 0
}

func syncDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readOwnerOnly(path string, maximum int64, afterRead func()) ([]byte, error) {
	if !filepath.IsAbs(path) || maximum < 1 {
		return nil, errors.New("private artifact input path or size bound is invalid")
	}
	directory := filepath.Dir(path)
	name := filepath.Base(path)

	var selectedParent unix.Stat_t
	if err := unix.Lstat(directory, &selectedParent); err != nil || !trustedParent(selectedParent) {
		return nil, errors.New("private artifact input directory is not trusted")
	}
	// #nosec G304 -- path is a cleaned absolute operator-selected directory;
	// O_NOFOLLOW and the descriptor/path identity checks prevent final-link use.
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open private artifact input directory")
	}
	defer unix.Close(directoryFD)
	var openedParent unix.Stat_t
	if err := unix.Fstat(directoryFD, &openedParent); err != nil || !sameParent(selectedParent, openedParent) || !trustedParent(openedParent) {
		return nil, errors.New("private artifact input directory changed while opening")
	}

	var selected unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &selected, unix.AT_SYMLINK_NOFOLLOW); err != nil || !protectedRegularFile(selected, maximum) {
		return nil, errors.New("private artifact input is not an exact owner-only regular file")
	}
	fileFD, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("open private artifact input")
	}
	file := os.NewFile(uintptr(fileFD), name)
	if file == nil {
		_ = unix.Close(fileFD)
		return nil, errors.New("adopt private artifact input")
	}
	defer file.Close()

	var opened unix.Stat_t
	if err := unix.Fstat(fileFD, &opened); err != nil || !sameArtifact(selected, opened) || !protectedRegularFile(opened, maximum) {
		return nil, errors.New("private artifact input changed while opening")
	}
	before, err := file.Stat()
	if err != nil {
		return nil, errors.New("inspect private artifact input")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) != opened.Size || int64(len(payload)) > maximum {
		zeroBytes(payload)
		return nil, errors.New("read exact bounded private artifact input")
	}
	if afterRead != nil {
		afterRead()
	}

	after, statErr := file.Stat()
	var openedAfter, selectedAfter, parentAfter unix.Stat_t
	descriptorErr := unix.Fstat(fileFD, &openedAfter)
	pathErr := unix.Fstatat(directoryFD, name, &selectedAfter, unix.AT_SYMLINK_NOFOLLOW)
	parentErr := unix.Lstat(directory, &parentAfter)
	if statErr != nil || descriptorErr != nil || pathErr != nil || parentErr != nil ||
		!sameReadMetadata(before, after) || !sameArtifact(opened, openedAfter) || !sameArtifact(openedAfter, selectedAfter) ||
		!protectedRegularFile(openedAfter, maximum) || !sameParent(selectedParent, parentAfter) {
		zeroBytes(payload)
		return nil, errors.New("private artifact input changed while reading")
	}
	return payload, nil
}

func trustedParent(stat unix.Stat_t) bool {
	owner := int64(stat.Uid)
	effectiveOwner := int64(os.Geteuid())
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR && (owner == 0 || owner == effectiveOwner) &&
		os.FileMode(stat.Mode).Perm()&0o022 == 0
}

func protectedRegularFile(stat unix.Stat_t, maximum int64) bool {
	permissions := os.FileMode(stat.Mode).Perm()
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && int64(stat.Uid) == int64(os.Geteuid()) && stat.Nlink == 1 &&
		(permissions == 0o400 || permissions == 0o600) && stat.Size > 0 && stat.Size <= maximum
}

func sameParent(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Uid == right.Uid && left.Gid == right.Gid
}

func sameArtifact(left, right unix.Stat_t) bool {
	return sameParent(left, right) && left.Nlink == right.Nlink && left.Size == right.Size
}

func sameReadMetadata(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Mode() == right.Mode() &&
		left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}
