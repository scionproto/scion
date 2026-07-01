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
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrintNetworkStatus checks the rendered live-status table: one row per
// configured address, with the link state and per-address presence.
func TestPrintNetworkStatus(t *testing.T) {
	statuses := []interfaceStatus{
		{
			name:   "eth1",
			exists: true,
			up:     true,
			addrs:  []addrStatus{{addr: "10.1.1.1/30", present: true}},
		},
		{
			name:   "mgmt",
			exists: false,
			addrs:  []addrStatus{{addr: "192.168.1.11/24", present: false}},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, printNetworkStatus(&buf, statuses))
	out := buf.String()
	for _, want := range []string{
		"INTERFACE", "LINK", "ADDRESS", "STATUS",
		"eth1", "up", "10.1.1.1/30", "present",
		"mgmt", "missing", "192.168.1.11/24",
	} {
		assert.Containsf(t, out, want, "printNetworkStatus output missing %q", want)
	}
}

// TestWaitForLinkTimeout checks that waiting for an interface that never appears
// returns nil after the timeout instead of blocking forever. (A read-only link
// lookup needs no privileges, so this runs in a plain `go test`.)
func TestWaitForLinkTimeout(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	const timeout = 200 * time.Millisecond

	start := time.Now()
	link := waitForLink("clab-test-nonexistent0", timeout, 20*time.Millisecond, log)
	elapsed := time.Since(start)

	require.Nil(t, link, "expected nil for a nonexistent interface")
	assert.GreaterOrEqualf(t, elapsed, timeout, "returned before the %v timeout", timeout)
	assert.LessOrEqual(t, elapsed, 5*time.Second, "wait did not honor the timeout")
}
