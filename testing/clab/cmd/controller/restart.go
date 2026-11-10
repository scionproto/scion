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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// A restart request asks the running controller to restart a service right
// away, e.g. after its configuration file was changed. The `services restart`
// CLI is a separate process: it marks the service with a request file next to
// the status file and then terminates the service. When the supervisor reaps
// the service and finds the request, it restarts the service immediately and
// resets its crash backoff, instead of treating the exit as a crash.
//
// The request file holds the PID of the process to restart. The supervisor
// honors the request only when exactly that process exits. A request that
// outlived its process, e.g. because the service exited for another reason
// first, is discarded, so that it cannot turn a later crash into a requested
// restart.

// restartRequestDir is the directory of the restart request files, next to the
// status file.
func restartRequestDir(statusFile string) string {
	return filepath.Join(filepath.Dir(statusFile), "restart")
}

// requestRestart creates the restart request file for the process pid of the
// named service.
func requestRestart(statusFile, name string, pid int) error {
	dir := restartRequestDir(statusFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), []byte(strconv.Itoa(pid)), 0o644)
}

// consumeRestartRequest reports whether a restart was requested for the
// process pid of the named service. It removes any request for the service,
// also one for another process.
func consumeRestartRequest(statusFile, name string, pid int) bool {
	if statusFile == "" {
		return false
	}
	path := filepath.Join(restartRequestDir(statusFile), name)
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	_ = os.Remove(path)
	requested, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	return err == nil && requested == pid
}

// clearRestartRequests removes all restart requests. The supervisor calls it on
// start: requests of a previous controller refer to processes that are gone,
// and their PIDs may be reused.
func clearRestartRequests(statusFile string) error {
	if statusFile == "" {
		return nil
	}
	return os.RemoveAll(restartRequestDir(statusFile))
}

// restartServices restarts the named services of the running controller and
// waits until each of them runs again with a new process, or until timeout.
// The new process must then keep running for settle, so that a service that
// exits right away, e.g. because of a bad configuration, fails the restart.
func restartServices(
	statusFile string,
	names []string,
	timeout time.Duration,
	settle time.Duration,
) error {
	statuses, err := readStatusFile(statusFile)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("controller not running (no status file %q)", statusFile)
	}
	if err != nil {
		return err
	}
	byName := map[string]serviceStatus{}
	for _, s := range statuses {
		byName[s.Name] = s
	}
	// Restart every service once, even if it is named several times.
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	// Validate all names first, so that a typo does not restart only some.
	for _, name := range names {
		s, ok := byName[name]
		if !ok {
			return fmt.Errorf("unknown service %q", name)
		}
		if !s.Running || s.PID == 0 {
			return fmt.Errorf("service %q is not running", name)
		}
	}
	// Terminate all services, and wait for the ones that were terminated even
	// if terminating another one failed, so that the result covers every
	// service that is restarting.
	errs := make([]error, len(names))
	terminated := make([]bool, len(names))
	for i, name := range names {
		pid := byName[name].PID
		if err := requestRestart(statusFile, name, pid); err != nil {
			errs[i] = fmt.Errorf("requesting restart of %q: %w", name, err)
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			consumeRestartRequest(statusFile, name, pid)
			errs[i] = fmt.Errorf("terminating %q (pid %d): %w", name, pid, err)
			continue
		}
		terminated[i] = true
	}
	var wg sync.WaitGroup
	for i, name := range names {
		if !terminated[i] {
			continue
		}
		wg.Go(func() {
			errs[i] = awaitRestart(statusFile, name, byName[name].PID, timeout, settle)
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

// awaitRestart polls the status file until the named service runs with a PID
// other than oldPID, and then checks that the new process keeps running for
// settle. It fails if the service does not start within timeout, or if the new
// process exits during the settle time.
//
// On a requested restart, the supervisor reaps the old process and starts the
// new one without publishing a status in between. A status that shows the
// service as not running therefore means that the new process exited already,
// even if it ran too briefly for a poll to see its PID.
func awaitRestart(
	statusFile, name string,
	oldPID int,
	timeout, settle time.Duration,
) error {
	deadline := time.Now().Add(timeout)
	var newPID int
	var settled time.Time
	for {
		var current *serviceStatus
		if statuses, err := readStatusFile(statusFile); err == nil {
			for _, s := range statuses {
				if s.Name == name {
					current = &s
					break
				}
			}
		}
		running := current != nil && current.Running && current.PID != 0
		switch {
		case newPID == 0 && current != nil && !running:
			return fmt.Errorf("service %q exited right after the restart (%s)",
				name, lastExit(current))
		case newPID == 0 && running && current.PID != oldPID:
			newPID = current.PID
			settled = time.Now().Add(settle)
		case newPID != 0 && (!running || current.PID != newPID):
			return fmt.Errorf("service %q exited right after the restart (pid %d, %s)",
				name, newPID, lastExit(current))
		case newPID != 0 && !time.Now().Before(settled):
			return nil
		case newPID == 0 && time.Now().After(deadline):
			return fmt.Errorf("service %q did not restart within %s", name, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// lastExit describes the last exit of the service in status s.
func lastExit(s *serviceStatus) string {
	if s == nil || s.LastExit == "" {
		return "unknown exit"
	}
	return s.LastExit
}
