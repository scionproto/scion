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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestLoadNetworkConfig checks that the same configuration parses identically
// whether supplied as JSON or YAML, since the controller accepts either.
func TestLoadNetworkConfig(t *testing.T) {
	const jsonCfg = `{
  "config": {
    "interfaces": {
      "ethernets": [
        {
          "addresses": ["169.254.10.9/30"],
          "name": "wan"
        },
        {
          "addresses": ["192.168.1.11/24"],
          "name": "mgmt"
        }
      ]
    }
  }
}`
	const yamlCfg = `config:
  interfaces:
    ethernets:
      - name: wan
        addresses:
          - 169.254.10.9/30
      - name: mgmt
        addresses:
          - 192.168.1.11/24
`

	want := []ethernet{
		{Name: "wan", Addresses: []string{"169.254.10.9/30"}},
		{Name: "mgmt", Addresses: []string{"192.168.1.11/24"}},
	}

	for _, tc := range []struct{ name, ext, data string }{
		{name: "json", ext: ".json", data: jsonCfg},
		{name: "yaml", ext: ".yaml", data: yamlCfg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "network"+tc.ext)
			if err := os.WriteFile(path, []byte(tc.data), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadNetworkConfig(path)
			if err != nil {
				t.Fatalf("loadNetworkConfig: %v", err)
			}
			if got := cfg.Config.Interfaces.Ethernets; !reflect.DeepEqual(got, want) {
				t.Errorf("parsed mismatch:\n got: %+v\nwant: %+v", got, want)
			}
		})
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
