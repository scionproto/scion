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
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/testing/clab/cmd/controller/config"
)

// TestMain lets the test binary impersonate both the controller and the SCION
// service binaries it supervises, so the end-to-end test needs no shell and no
// external executables: the binaries under --bin-dir are symlinks back to this
// test binary. The CLAB_TEST_ROLE env var (set on the controller subprocess and
// inherited by its children) gates the impersonation, so a plain `go test` run
// never enters these branches.
func TestMain(m *testing.M) {
	if os.Getenv("CLAB_TEST_ROLE") == "controller" {
		switch filepath.Base(os.Args[0]) {
		case "router", "daemon", "dispatcher":
			fakeRunUntilSignal() // long-running, exits cleanly on SIGTERM
		case "control":
			fakeCrash() // crash-loops, to exercise restart/backoff
		default:
			main() // the controller itself
		}
		return
	}
	os.Exit(m.Run())
}

func fakeRunUntilSignal() {
	name := filepath.Base(os.Args[0])
	fmt.Printf("FAKE service=%s event=start\n", name)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
	fmt.Printf("FAKE service=%s event=stop\n", name)
	os.Exit(0)
}

func fakeCrash() {
	fmt.Println("FAKE service=control event=crash")
	os.Exit(3)
}

func TestRenderServices(t *testing.T) {
	ia := addr.MustParseIA("1-ff00:0:110")
	cfg := config.Config{SCION: config.SCION{ASes: []config.AS{{
		ISDAS: ia,
		Core:  true,
		Router: &config.Router{
			ID:                "br1-ff00_0_110-1",
			InternalInterface: netip.MustParseAddrPort("10.1.0.1:30042"),
			APIAddr:           netip.MustParseAddrPort("10.1.0.1:30442"),
		},
		Control: &config.Control{
			ID:      "cs1-ff00_0_110-1",
			Address: netip.MustParseAddrPort("10.1.0.1:30252"),
			APIAddr: netip.MustParseAddrPort("10.1.0.1:30452"),
		},
		Daemon: &config.Daemon{
			ID:      "sd",
			Address: netip.MustParseAddrPort("127.0.0.1:30255"),
			APIAddr: netip.MustParseAddrPort("10.1.0.1:30455"),
		},
	}}}}

	confDir := t.TempDir()
	got, err := renderServices(cfg, confDir, "/app")
	if err != nil {
		t.Fatalf("renderServices: %v", err)
	}

	cfgArg := func(f string) []string { return []string{"--config", filepath.Join(confDir, f)} }
	// Dispatcher first (start order), then by service id.
	want := []service{
		{name: "disp_cs1-ff00_0_110-1", binary: "/app/dispatcher", args: cfgArg("disp_cs1-ff00_0_110-1.toml")},
		{name: "br1-ff00_0_110-1", binary: "/app/router", args: cfgArg("br1-ff00_0_110-1.toml")},
		{name: "cs1-ff00_0_110-1", binary: "/app/control", args: cfgArg("cs1-ff00_0_110-1.toml")},
		{name: "sd", binary: "/app/daemon", args: cfgArg("sd.toml")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("renderServices mismatch:\n got: %+v\nwant: %+v", got, want)
	}
	// Each service's config file was actually written to the config dir.
	for _, s := range want {
		if _, err := os.Stat(s.args[1]); err != nil {
			t.Errorf("expected rendered config %q: %v", s.args[1], err)
		}
	}
}

// TestPrintServices checks the rendered table lists each service with its
// binary and arguments.
func TestPrintServices(t *testing.T) {
	services := []service{
		{name: "br1-ff00_0_110-1", binary: "/app/router", args: []string{"--config", "/etc/scion/br1-ff00_0_110-1.toml"}},
		{name: "sd", binary: "/app/daemon", args: []string{"--config", "/etc/scion/sd.toml"}},
	}

	var buf bytes.Buffer
	if err := printServices(&buf, services); err != nil {
		t.Fatalf("printServices: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"SERVICE", "BINARY", "ARGS",
		"br1-ff00_0_110-1", "/app/router", "--config /etc/scion/br1-ff00_0_110-1.toml",
		"sd", "/app/daemon", "--config /etc/scion/sd.toml",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printServices output missing %q; got:\n%s", want, out)
		}
	}
}

// TestSupervise is the automated form of the manual smoke test: it runs the
// real controller against fake binaries and asserts it starts every service
// (including the dispatcher), restarts a crashing one with backoff, and shuts
// down cleanly on SIGTERM.
func TestSupervise(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	for _, b := range []string{"dispatcher", "router", "control", "daemon"} {
		if err := os.Symlink(exe, filepath.Join(binDir, b)); err != nil {
			t.Fatal(err)
		}
	}

	// The prism config drives everything: one router, one control (which also
	// yields a co-located dispatcher), and one daemon. The rendered service
	// files are written into cfgDir at startup.
	cfgDir := t.TempDir()
	cfg := config.Config{SCION: config.SCION{ASes: []config.AS{{
		ISDAS:   addr.MustParseIA("1-ff00:0:110"),
		Core:    true,
		Router:  &config.Router{ID: "br-test", APIAddr: netip.MustParseAddrPort("127.0.0.1:30442")},
		Control: &config.Control{ID: "cs-test", Address: netip.MustParseAddrPort("127.0.0.1:30252")},
		Daemon:  &config.Daemon{ID: "sd", Address: netip.MustParseAddrPort("127.0.0.1:30255")},
	}}}}
	cfgRaw, err := cfg.EncodeYAML()
	if err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(cfgDir, "config.yml")
	if err := os.WriteFile(configFile, cfgRaw, 0o644); err != nil {
		t.Fatal(err)
	}

	logDir := t.TempDir()
	statusFile := filepath.Join(t.TempDir(), "status.json")

	// One pipe for the controller's stdout+stderr; its children inherit the
	// same fds, so all output lands here without racing on the buffer.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe,
		"--config-dir", cfgDir,
		"--config-file", configFile,
		"--bin-dir", binDir,
		"--log-dir", logDir,
		"--status-file", statusFile,
		"--shutdown-timeout", "2s",
	)
	cmd.Env = append(os.Environ(), "CLAB_TEST_ROLE=controller")
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	w.Close() // children hold their own dups; EOF arrives once all exit.

	var out bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&out, r); close(done) }()

	// Give services time to start and the crash-looper to restart, then stop.
	time.Sleep(1500 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	waitErr := cmd.Wait()
	<-done
	logs := out.String()
	t.Logf("controller output:\n%s", logs)

	if waitErr != nil {
		t.Fatalf("controller did not exit cleanly on SIGTERM: %v", waitErr)
	}

	// Every service, including the dispatcher, was started.
	for _, name := range []string{"disp_cs-test", "br-test", "cs-test", "sd"} {
		if !strings.Contains(logs, `msg="started service" service=`+name) {
			t.Errorf("service %q was never started", name)
		}
	}
	if !strings.Contains(logs, "FAKE service=dispatcher event=start") {
		t.Error("dispatcher binary was not executed")
	}

	// The crashing control service was restarted with backoff.
	if crashes := strings.Count(logs, "FAKE service=control event=crash"); crashes < 2 {
		t.Errorf("expected control to crash and restart at least twice, got %d", crashes)
	}
	if !strings.Contains(logs, `msg="scheduling restart" service=cs-test`) {
		t.Error("control crash did not trigger a scheduled restart")
	}

	// Clean shutdown: long-running services received SIGTERM and the
	// controller exited only after the last child was reaped.
	for _, name := range []string{"dispatcher", "router", "daemon"} {
		if !strings.Contains(logs, fmt.Sprintf("FAKE service=%s event=stop", name)) {
			t.Errorf("service %q did not receive a clean shutdown signal", name)
		}
	}
	if !strings.Contains(logs, "all services stopped; exiting") {
		t.Error("controller did not report a clean shutdown")
	}

	// Service output in the merged stream is tagged with the service name.
	if !strings.Contains(logs, "[disp_cs-test] FAKE service=dispatcher event=start") {
		t.Error("merged log stream is not prefixed with the service name")
	}
	// The controller's own diagnostics are tagged too.
	if !strings.Contains(logs, `[controller] `) ||
		!strings.Contains(logs, `[controller] time=`) {
		t.Error("controller log lines are not prefixed with [controller]")
	}

	// Each service also got its own log file, carrying its raw (unprefixed)
	// output.
	for name, want := range map[string]string{
		"disp_cs-test": "FAKE service=dispatcher event=start",
		"br-test":   "FAKE service=router event=start",
		"sd":        "FAKE service=daemon event=start",
		"cs-test":   "FAKE service=control event=crash",
	} {
		data, err := os.ReadFile(filepath.Join(logDir, name+".log"))
		if err != nil {
			t.Errorf("reading log file for %q: %v", name, err)
			continue
		}
		if !strings.Contains(string(data), want) {
			t.Errorf("log file for %q missing %q; got:\n%s", name, want, data)
		}
	}

	// The controller published live status to the status file, listing every
	// service, and recorded the crash-looper's restarts and last exit.
	statuses, err := readStatusFile(statusFile)
	if err != nil {
		t.Fatalf("reading status file: %v", err)
	}
	byName := make(map[string]serviceStatus, len(statuses))
	for _, s := range statuses {
		byName[s.Name] = s
	}
	for _, name := range []string{"disp_cs-test", "br-test", "cs-test", "sd"} {
		if _, ok := byName[name]; !ok {
			t.Errorf("status file missing service %q; got %+v", name, statuses)
		}
	}
	if cs := byName["cs-test"]; cs.Restarts == 0 || cs.LastExit == "" {
		t.Errorf("crash-looping control should show restarts and a last exit; got %+v", cs)
	}
}
