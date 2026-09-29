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
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// maxLogLine caps the length of a single service log line the controller will
// buffer before splitting it; SCION logs can be long (stack traces, certs).
const maxLogLine = 1024 * 1024

const (
	// backoffBase is the initial restart delay; it doubles per consecutive
	// crash up to backoffMax.
	backoffBase = 500 * time.Millisecond
	// backoffMax caps the restart backoff.
	backoffMax = 30 * time.Second
	// stableAfter is how long a process must stay up before its crash backoff
	// is reset, so a service that runs fine for a while restarts promptly.
	stableAfter = 60 * time.Second
)

// managed is the supervisor's bookkeeping for one service.
type managed struct {
	svc       service
	proc      *os.Process
	restarts  int
	startedAt time.Time
	// lastExit describes the most recent exit, or is empty if the service has
	// not exited yet. Surfaced through the status file for `list services`.
	lastExit string
}

// supervisor runs as PID 1: it starts the discovered services, reaps every
// child (including reparented orphans) centrally from the SIGCHLD handler,
// restarts crashed services with backoff, and forwards termination signals
// for a clean shutdown.
//
// All reaping happens in one place via Wait4(-1, ...). Per-child cmd.Wait()
// is deliberately avoided: it would race the central reaper and fail with
// "waitid: no child process".
type supervisor struct {
	log             *slog.Logger
	shutdownTimeout time.Duration
	// logDir, if non-empty, is where per-service "<name>.log" files are
	// written (in addition to the merged, prefixed stream on out).
	logDir string
	// statusPath, if non-empty, is the file the supervisor rewrites on every
	// service state change so `list services` can report live status.
	statusPath string

	// out receives the merged, per-line-prefixed output of all services.
	// outMu serializes writes so lines from different services never tear.
	out   io.Writer
	outMu sync.Mutex
	// pumps tracks the per-service log-forwarding goroutines so a clean
	// shutdown can drain them before exiting and not lose final log lines.
	pumps sync.WaitGroup

	mu           sync.Mutex
	services     []*managed
	byPID        map[int]*managed
	shuttingDown bool
}

func newSupervisor(
	services []service,
	log *slog.Logger,
	shutdownTimeout time.Duration,
	logDir string,
	statusPath string,
) *supervisor {
	managedSvcs := make([]*managed, len(services))
	for i, svc := range services {
		managedSvcs[i] = &managed{svc: svc}
	}
	return &supervisor{
		log:             log,
		shutdownTimeout: shutdownTimeout,
		logDir:          logDir,
		statusPath:      statusPath,
		out:             os.Stdout,
		services:        managedSvcs,
		byPID:           make(map[int]*managed),
	}
}

// run starts all services and processes signals until shutdown. It only
// returns if the signal channel is closed; on a clean shutdown it calls
// os.Exit from within the signal loop once the last child is reaped.
func (s *supervisor) run() {
	// Register before starting children so no early SIGCHLD is missed.
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	s.mu.Lock()
	for _, m := range s.services {
		s.startLocked(m)
	}
	s.mu.Unlock()

	for sig := range sigs {
		switch sig {
		case syscall.SIGCHLD:
			s.reap()
		case syscall.SIGHUP:
			// Forward to services that reload topology on SIGHUP (control,
			// daemon). The router ignores it and reloads only on restart.
			s.forward(syscall.SIGHUP)
		case syscall.SIGTERM, syscall.SIGINT:
			s.beginShutdown(sig)
		}
	}
}

// startLocked launches m's process and records it. The caller must hold s.mu.
//
// The child's stdout and stderr are wired to a pipe that the controller reads
// and forwards line-by-line, tagged with the service name, so the merged
// container log stays attributable (see pump).
func (s *supervisor) startLocked(m *managed) {
	cmd := exec.Command(m.svc.binary, m.svc.args...)
	r, w, err := os.Pipe()
	if err != nil {
		s.log.Error("failed to create log pipe", "service", m.svc.name, "err", err)
		s.scheduleRestartLocked(m)
		return
	}
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		w.Close()
		r.Close()
		s.log.Error("failed to start service", "service", m.svc.name, "err", err)
		s.scheduleRestartLocked(m)
		return
	}
	// The child holds its own dup of w; we only read from r. Closing our copy
	// of w lets the pump see EOF once the child (and any forks) exit.
	w.Close()
	s.pumps.Add(1)
	go s.pump(m.svc.name, r)

	m.proc = cmd.Process
	m.startedAt = time.Now()
	s.byPID[cmd.Process.Pid] = m
	s.log.Info("started service", "service", m.svc.name, "pid", cmd.Process.Pid)
	s.persistStatusLocked()
}

// pump forwards one service's output from r until EOF. Every line is written
// to the merged stream (prefixed with "[name] ") and, if a log directory is
// configured, appended verbatim to "<logDir>/<name>.log". The per-service file
// is opened in append mode so output survives across restarts.
func (s *supervisor) pump(name string, r *os.File) {
	defer s.pumps.Done()
	defer r.Close()

	var file *os.File
	if s.logDir != "" {
		path := filepath.Join(s.logDir, name+".log")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			s.log.Warn("cannot open service log file; using stdout only",
				"service", name, "path", path, "err", err)
		} else {
			file = f
			defer file.Close()
		}
	}

	prefix := []byte("[" + name + "] ")
	nl := []byte{'\n'}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLogLine)
	for scanner.Scan() {
		line := scanner.Bytes()
		if file != nil {
			_, _ = file.Write(line)
			_, _ = file.Write(nl)
		}
		s.outMu.Lock()
		_, _ = s.out.Write(prefix)
		_, _ = s.out.Write(line)
		_, _ = s.out.Write(nl)
		s.outMu.Unlock()
	}
	if err := scanner.Err(); err != nil {
		s.log.Warn("error reading service output", "service", name, "err", err)
	}
}

// reap drains all currently-exited children. SIGCHLD coalesces, so we loop
// with WNOHANG until no more children are waitable.
func (s *supervisor) reap() {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if pid <= 0 {
			// 0: a child exists but has not exited. -1 (ECHILD): no children.
			_ = err
			return
		}

		s.mu.Lock()
		m, ok := s.byPID[pid]
		if !ok {
			// A reparented orphan grandchild; reaping it is all that's needed.
			s.mu.Unlock()
			s.log.Debug("reaped orphan", "pid", pid)
			continue
		}
		delete(s.byPID, pid)
		m.proc = nil
		if ws.Signaled() {
			m.lastExit = fmt.Sprintf("signal %s", ws.Signal())
			s.log.Info("service exited", "service", m.svc.name, "pid", pid, "signal", ws.Signal())
		} else {
			m.lastExit = fmt.Sprintf("exit code %d", ws.ExitStatus())
			s.log.Info("service exited",
				"service", m.svc.name,
				"pid", pid,
				"exit_code", ws.ExitStatus(),
			)
		}

		switch {
		case s.shuttingDown:
			s.persistStatusLocked()
			if len(s.byPID) == 0 {
				s.log.Info("all services stopped; exiting")
				s.mu.Unlock()
				// Drain the log pumps so the services' final lines are not
				// lost. EOF is guaranteed: every child has exited.
				s.pumps.Wait()
				os.Exit(0)
			}
		default:
			s.scheduleRestartLocked(m)
		}
		s.mu.Unlock()
	}
}

// scheduleRestartLocked arms a delayed restart of m using crash backoff. The caller
// must hold s.mu; the restart itself reacquires it when the timer fires.
func (s *supervisor) scheduleRestartLocked(m *managed) {
	if !m.startedAt.IsZero() && time.Since(m.startedAt) > stableAfter {
		m.restarts = 0
	}
	delay := min(backoffBase<<min(m.restarts, 6), backoffMax)
	m.restarts++
	m.proc = nil
	s.log.Info("scheduling restart",
		"service", m.svc.name, "delay", delay, "attempt", m.restarts)
	s.persistStatusLocked()

	time.AfterFunc(delay, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.shuttingDown {
			return
		}
		s.startLocked(m)
	})
}

// persistStatusLocked rewrites the status file from the current managed state.
// The caller must hold s.mu. It is best-effort: a write error is logged and the
// supervisor carries on (status reporting must never take the node down).
func (s *supervisor) persistStatusLocked() {
	if s.statusPath == "" {
		return
	}
	statuses := make([]serviceStatus, len(s.services))
	for i, m := range s.services {
		st := serviceStatus{
			Name:     m.svc.name,
			Binary:   m.svc.binary,
			Restarts: m.restarts,
			LastExit: m.lastExit,
		}
		if m.proc != nil {
			st.Running = true
			st.PID = m.proc.Pid
			st.StartedAt = m.startedAt
		}
		statuses[i] = st
	}
	if err := writeStatusFile(s.statusPath, statuses); err != nil {
		s.log.Warn("failed to write status file", "path", s.statusPath, "err", err)
	}
}

// forward relays sig to every running managed service.
func (s *supervisor) forward(sig syscall.Signal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.byPID {
		if m.proc != nil {
			_ = m.proc.Signal(sig)
		}
	}
}

// beginShutdown switches the supervisor to shutdown mode, signals all children
// to terminate, and escalates to SIGKILL after the grace period. Exit happens
// in reap() once the last child is reaped, with a hard backstop here.
func (s *supervisor) beginShutdown(sig os.Signal) {
	s.mu.Lock()
	if s.shuttingDown {
		s.mu.Unlock()
		return
	}
	s.shuttingDown = true
	if len(s.byPID) == 0 {
		s.mu.Unlock()
		os.Exit(0)
	}
	s.log.Info("shutting down", "signal", sig.String(), "services", len(s.byPID))
	for _, m := range s.byPID {
		if m.proc != nil {
			_ = m.proc.Signal(syscall.SIGTERM)
		}
	}
	s.mu.Unlock()

	// Escalate to SIGKILL for stragglers.
	time.AfterFunc(s.shutdownTimeout, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for pid, m := range s.byPID {
			s.log.Warn("service did not stop in time; killing",
				"service", m.svc.name, "pid", pid)
			if m.proc != nil {
				_ = m.proc.Signal(syscall.SIGKILL)
			}
		}
	})

	// Hard backstop: exit even if a child is unkillable (e.g. stuck in D).
	time.AfterFunc(2*s.shutdownTimeout, func() {
		s.log.Error("shutdown timed out; exiting forcibly")
		os.Exit(1)
	})
}
