// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConsumeRestartRequest checks that a restart request is honored only for
// the process it was made for, and that a stale request is discarded.
func TestConsumeRestartRequest(t *testing.T) {
	statusFile := filepath.Join(t.TempDir(), "status.json")
	request := filepath.Join(restartRequestDir(statusFile), "br")

	// No request.
	assert.False(t, consumeRestartRequest(statusFile, "br", 42))

	// A request for the process that exited.
	require.NoError(t, requestRestart(statusFile, "br", 42))
	assert.True(t, consumeRestartRequest(statusFile, "br", 42))
	assert.NoFileExists(t, request)
	assert.False(t, consumeRestartRequest(statusFile, "br", 42), "request consumed twice")

	// A stale request for an earlier process: not honored, but discarded, so
	// that it cannot affect a later exit either.
	require.NoError(t, requestRestart(statusFile, "br", 42))
	assert.False(t, consumeRestartRequest(statusFile, "br", 43))
	assert.NoFileExists(t, request)

	// Requests of a previous controller are cleared on start.
	require.NoError(t, requestRestart(statusFile, "br", 42))
	require.NoError(t, clearRestartRequests(statusFile))
	assert.False(t, consumeRestartRequest(statusFile, "br", 42))
}

// TestAwaitRestart checks that awaitRestart succeeds only if the new process
// keeps running for the settle time.
func TestAwaitRestart(t *testing.T) {
	const (
		oldPID  = 100
		newPID  = 101
		timeout = 5 * time.Second
		settle  = 300 * time.Millisecond
	)
	running := func(pid int) []serviceStatus {
		return []serviceStatus{{Name: "br", Running: true, PID: pid}}
	}

	t.Run("stays up", func(t *testing.T) {
		statusFile := filepath.Join(t.TempDir(), "status.json")
		require.NoError(t, writeStatusFile(statusFile, running(newPID)))
		start := time.Now()
		require.NoError(t, awaitRestart(statusFile, "br", oldPID, timeout, settle))
		assert.GreaterOrEqual(t, time.Since(start), settle)
	})

	t.Run("exits right away", func(t *testing.T) {
		statusFile := filepath.Join(t.TempDir(), "status.json")
		require.NoError(t, writeStatusFile(statusFile, running(newPID)))
		go func() {
			time.Sleep(settle / 3)
			_ = writeStatusFile(statusFile, []serviceStatus{
				{Name: "br", LastExit: "exit code 1"},
			})
		}()
		err := awaitRestart(statusFile, "br", oldPID, timeout, settle)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exit code 1")
	})

	t.Run("exits before the first poll", func(t *testing.T) {
		statusFile := filepath.Join(t.TempDir(), "status.json")
		// The new process already exited and waits for its crash restart.
		require.NoError(t, writeStatusFile(statusFile, []serviceStatus{
			{Name: "br", LastExit: "exit code 2", Restarts: 1},
		}))
		err := awaitRestart(statusFile, "br", oldPID, timeout, settle)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exit code 2")
	})

	t.Run("no new process", func(t *testing.T) {
		statusFile := filepath.Join(t.TempDir(), "status.json")
		require.NoError(t, writeStatusFile(statusFile, running(oldPID)))
		err := awaitRestart(statusFile, "br", oldPID, 300*time.Millisecond, settle)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "did not restart")
	})

	t.Run("no status file", func(t *testing.T) {
		statusFile := filepath.Join(t.TempDir(), "missing", "status.json")
		_, err := os.Stat(statusFile)
		require.ErrorIs(t, err, os.ErrNotExist)
		err = awaitRestart(statusFile, "br", oldPID, 300*time.Millisecond, settle)
		require.Error(t, err)
	})
}
