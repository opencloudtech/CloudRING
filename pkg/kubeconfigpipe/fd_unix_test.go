//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package kubeconfigpipe

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDuplicateFDIsAtomicallyCloseOnExecAndNotInherited(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	duplicate, err := duplicateFD(int(reader.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer duplicate.Close()
	flags, err := unix.FcntlInt(duplicate.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("duplicated kubeconfig descriptor is not close-on-exec")
	}
	fdPath := fmt.Sprintf("/dev/fd/%d", duplicate.Fd())
	// #nosec G204 -- test-only fixed shell and script; fdPath is derived only from the local numeric descriptor.
	if err := exec.Command("/bin/sh", "-c", `test ! -e "$1"`, "sh", fdPath).Run(); err != nil {
		t.Fatal("duplicated kubeconfig descriptor was inherited by an unrelated exec")
	}
}
