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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"
)

// serviceStatus is the live state of one supervised service, published by the
// running controller to the status file and read back by `list services`. The
// supervisor is the only writer; the inspection CLI is a separate process and
// cannot see the supervisor's in-memory state directly.
type serviceStatus struct {
	Name      string    `json:"name"`
	Binary    string    `json:"binary"`
	Running   bool      `json:"running"`
	PID       int       `json:"pid,omitempty"`
	Restarts  int       `json:"restarts"`
	StartedAt time.Time `json:"started_at"`
	// LastExit is a human-readable description of the most recent exit
	// ("exit code 1", "signal terminated"), or empty if the service has not
	// exited yet. A non-empty value on a running service means it crashed and
	// was restarted.
	LastExit string `json:"last_exit,omitempty"`
}

// writeStatusFile atomically writes the status snapshot as JSON to path, so a
// concurrent reader never sees a partial file. A best-effort facility: callers
// log and continue on error.
func writeStatusFile(path string, statuses []serviceStatus) error {
	data, err := json.MarshalIndent(statuses, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".status-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// readStatusFile reads the status snapshot written by the running controller.
func readStatusFile(path string) ([]serviceStatus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var statuses []serviceStatus
	if err := json.Unmarshal(data, &statuses); err != nil {
		return nil, fmt.Errorf("parsing status file %q: %w", path, err)
	}
	return statuses, nil
}

// printServiceStatus writes the live service status as an aligned table.
func printServiceStatus(w io.Writer, statuses []serviceStatus, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tSTATUS\tPID\tRESTARTS\tUPTIME\tLAST EXIT")
	for _, s := range statuses {
		state := "stopped"
		pid := "-"
		uptime := "-"
		if s.Running {
			state = "running"
			pid = fmt.Sprintf("%d", s.PID)
			if !s.StartedAt.IsZero() {
				uptime = now.Sub(s.StartedAt).Round(time.Second).String()
			}
		}
		lastExit := s.LastExit
		if lastExit == "" {
			lastExit = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			s.Name, state, pid, s.Restarts, uptime, lastExit)
	}
	return tw.Flush()
}
