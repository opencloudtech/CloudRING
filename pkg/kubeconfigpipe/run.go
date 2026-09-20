// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package kubeconfigpipe

import (
	"errors"
	"os/exec"
)

type runError struct {
	command error
	cleanup error
	replay  error
}

func (failure *runError) Error() string { return "contained command failed" }

func (failure *runError) Unwrap() []error {
	return []error{failure.command, failure.cleanup, failure.replay}
}

// IsLifecycleFailure reports failures where command output cannot be trusted:
// process cleanup, replay completion, or inherited-I/O WaitDelay expiry.
func IsLifecycleFailure(err error) bool {
	var failure *runError
	return errors.As(err, &failure) &&
		(failure.cleanup != nil || failure.replay != nil || errors.Is(failure.command, exec.ErrWaitDelay))
}

// Run executes one configured command inside the platform process-tree
// boundary. When replay is non-nil, it attaches a fresh pipe-backed kubeconfig.
// Process-tree cleanup always finishes before replay completion, so a child
// cannot keep either inherited output descriptors or the replay writer blocked.
func Run(command *exec.Cmd, replay *Replay) error {
	return run(command, replay, nil)
}

// RunWithEnvironmentNames preserves only explicitly named additional variables
// from command.Env across the replay boundary. It never reads ambient values.
// Callers must review these names as part of trusting the child executable.
func RunWithEnvironmentNames(command *exec.Cmd, replay *Replay, environmentNames []string) error {
	if command == nil || command.Env == nil || ValidateEnvironmentNames(environmentNames) != nil {
		return errors.New("invalid explicit kubeconfig command environment")
	}
	return run(command, replay, environmentNames)
}

func run(command *exec.Cmd, replay *Replay, environmentNames []string) error {
	if command == nil || command.Process != nil {
		return errors.New("invalid kubeconfig command")
	}
	configureProcessTree(command)
	complete := func() error { return nil }
	if replay != nil {
		var err error
		complete, err = replay.attach(command, environmentNames)
		if err != nil {
			return err
		}
	}
	runErr := command.Run()
	cleanupErr := cleanupProcessTree(command)
	replayErr := complete()
	if cleanupErr != nil {
		cleanupErr = errors.New("command process-tree cleanup failed")
	}
	if runErr == nil && cleanupErr == nil && replayErr == nil {
		return nil
	}
	return &runError{command: runErr, cleanup: cleanupErr, replay: replayErr}
}
