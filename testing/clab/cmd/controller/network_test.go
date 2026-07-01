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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/prism"
)

// TestEthernets checks that the node's inter-AS data-plane interfaces are
// extracted from the prism configuration's interfaces section.
func TestEthernets(t *testing.T) {
	cfg := prism.Config{
		Interfaces: prism.Interfaces{
			Ethernets: []prism.Ethernet{
				{Name: "eth1", Addresses: []string{"169.254.10.9/30"}},
				{Name: "eth2", Addresses: []string{"192.168.1.11/24"}},
			},
		},
	}

	want := []ethernet{
		{Name: "eth1", Addresses: []string{"169.254.10.9/30"}},
		{Name: "eth2", Addresses: []string{"192.168.1.11/24"}},
	}
	if got := ethernets(cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("ethernets mismatch:\n got: %+v\nwant: %+v", got, want)
	}
}

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
	if err := printNetworkStatus(&buf, statuses); err != nil {
		t.Fatalf("printNetworkStatus: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"INTERFACE", "LINK", "ADDRESS", "STATUS",
		"eth1", "up", "10.1.1.1/30", "present",
		"mgmt", "missing", "192.168.1.11/24",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printNetworkStatus output missing %q; got:\n%s", want, out)
		}
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

	if link != nil {
		t.Fatalf("expected nil for a nonexistent interface, got %v", link)
	}
	if elapsed < timeout {
		t.Errorf("returned after %v, before the %v timeout", elapsed, timeout)
	}
	if elapsed > 5*time.Second {
		t.Errorf("took %v; wait did not honor the timeout", elapsed)
	}
}
