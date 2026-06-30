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
	"bytes"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestStatusFileRoundTrip checks that a status snapshot survives a write/read
// cycle unchanged, since the controller writes it and a separate `list
// services` process reads it.
func TestStatusFileRoundTrip(t *testing.T) {
	want := []serviceStatus{
		{Name: "br1-ff00_0_110-1", Binary: "/app/router", Running: true, PID: 42,
			Restarts: 0, StartedAt: time.Unix(1700000000, 0).UTC()},
		{Name: "cs1-ff00_0_110-1", Binary: "/app/control", Running: false,
			Restarts: 5, LastExit: "exit code 1"},
	}

	path := filepath.Join(t.TempDir(), "status.json")
	if err := writeStatusFile(path, want); err != nil {
		t.Fatalf("writeStatusFile: %v", err)
	}
	got, err := readStatusFile(path)
	if err != nil {
		t.Fatalf("readStatusFile: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip mismatch:\n got: %+v\nwant: %+v", got, want)
	}
}

// TestPrintServiceStatus checks the rendered table reports running/stopped
// state, PID, restart count, and last exit.
func TestPrintServiceStatus(t *testing.T) {
	now := time.Unix(1700000090, 0).UTC()
	statuses := []serviceStatus{
		{Name: "br1-ff00_0_110-1", Running: true, PID: 42,
			StartedAt: time.Unix(1700000000, 0).UTC()},
		{Name: "cs1-ff00_0_110-1", Running: false, Restarts: 5, LastExit: "exit code 1"},
	}

	var buf bytes.Buffer
	if err := printServiceStatus(&buf, statuses, now); err != nil {
		t.Fatalf("printServiceStatus: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"SERVICE", "STATUS", "PID", "RESTARTS", "UPTIME", "LAST EXIT",
		"br1-ff00_0_110-1", "running", "42", "1m30s",
		"cs1-ff00_0_110-1", "stopped", "5", "exit code 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printServiceStatus output missing %q; got:\n%s", want, out)
		}
	}
}
