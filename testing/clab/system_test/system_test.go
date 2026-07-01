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

// Package system_test drives a containerlab SCION topology end to end. It runs
// in three phases:
//
//   - setup:    load the node image, generate the topology with testgen, and
//     deploy the containerlab topology;
//   - execute:  run the e2e_scion and e2e_http tests against the deployed lab;
//   - teardown: destroy the containerlab topology.
//
// The phases are selected with the -setup, -execute and -teardown flags. If
// none are set, all three run in order (setup, execute, teardown), with
// teardown always running even if execute fails. Selecting a subset lets a
// developer iterate: e.g. -setup once, then -execute repeatedly, then
// -teardown.
//
// The test is built to run under bazel only. All binaries and the node image
// are passed in via environment variables (set with $(rootpath ...) in the
// go_test target and resolved through the runfiles tree); the only external
// dependency is the `clab` command itself, which is assumed to be installed and
// is not tracked by bazel.
package system_test

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bazelbuild/rules_go/go/runfiles"
	"github.com/stretchr/testify/require"
)

var (
	labName  = flag.String("lab", "scion", "containerlab lab name")
	dockerC  = flag.String("docker", "docker", "docker command")
	clabC    = flag.String("clab", "clab", "containerlab command")
	topoFile = flag.String("topo", envOr("CLAB_TOPO", "topology/default-no-peers.topo"),
		"testgen topology description file",
	)

	// Phases

	runSetup = flag.Bool("setup", false,
		"run the setup phase (load image, generate topology, deploy)",
	)
	runExecute = flag.Bool("execute", false,
		"run the execute phase (e2e_scion, e2e_http)",
	)
	runTeardown = flag.Bool("teardown", false,
		"run the teardown phase (clab destroy)",
	)

	// artifactsFlag pins the working directory (where the lab is generated and
	// deployed). When running phases in separate bazel invocations (e.g. -setup
	// then -execute), each run gets a fresh TEST_TMPDIR, so the gen/ tree from
	// setup would not be visible to a later execute. Pass -artifacts to share a
	// directory across invocations.
	artifactsFlag = flag.String("artifacts", "",
		"working directory for the lab (default: TEST_TMPDIR/clab, else a temp dir)")
)

// env names for the bazel-provided artifacts. The go_test target wires these to
// $(rootpath ...) paths.
const (
	envImageTar   = "CLAB_NODE_IMAGE_TAR"    // node image tarball, loaded with `docker load`
	envTestgenBin = "TESTGEN_BIN"            // testgen CLI
	envAwaitConn  = "AWAIT_CONNECTIVITY_BIN" // await_connectivity driver
	envE2EScion   = "E2E_SCION_BIN"          // e2e_scion driver
	envE2EHTTP    = "E2E_HTTP_BIN"           // e2e_http driver
)

// TestSystem runs the selected phases against a containerlab SCION topology.
func TestSystem(t *testing.T) {
	// When no phase is selected, run the whole lifecycle.
	all := !*runSetup && !*runExecute && !*runTeardown

	tb := newHarness(t)

	if all || *runTeardown {
		// teardown must run even if execute fails; register it first so it runs
		// last. When only -teardown is requested, this still cleans up a lab
		// left behind by a previous -setup run.
		t.Cleanup(func() { tb.teardown(t) })
	}
	if all || *runSetup {
		tb.setup(t)
	}
	if all || *runExecute {
		tb.execute(t)
	}
}

// harness holds the resolved artifact paths and the working/output directories.
type harness struct {
	// workDir is where the lab is generated and deployed. It is deliberately
	// NOT under TEST_UNDECLARED_OUTPUTS_DIR: the deployed containers run as root
	// and write into the bind-mounted gen/ tree (e.g. ASxxx/host-N/keys), so
	// after teardown it contains root-owned files with restrictive permissions
	// that bazel cannot collect as undeclared outputs ("Operation not
	// permitted"). Bazel does not validate TEST_TMPDIR, so the lab lives there.
	workDir string
	// outputsDir is TEST_UNDECLARED_OUTPUTS_DIR (empty if unset). Readable
	// summary artifacts (the clab topology, e2e output) are copied here so they
	// are collected like the acceptance tests.
	outputsDir string

	genDir  string
	clabYML string

	topo       string
	imageTar   string
	testgenBin string
	awaitConn  string
	e2eScion   string
	e2eHTTP    string
}

func newHarness(t *testing.T) *harness {
	workDir := workingDir(t)
	t.Logf("work dir: %s", workDir)
	outputsDir := os.Getenv("TEST_UNDECLARED_OUTPUTS_DIR")
	if outputsDir != "" {
		t.Logf("outputs dir: %s", outputsDir)
	}
	return &harness{
		workDir:    workDir,
		outputsDir: outputsDir,
		genDir:     filepath.Join(workDir, "gen"),
		clabYML:    filepath.Join(workDir, "gen", *labName+".clab.yml"),
		topo:       resolvePath(t, *topoFile),
		imageTar:   mustEnv(t, envImageTar),
		testgenBin: mustEnv(t, envTestgenBin),
		awaitConn:  mustEnv(t, envAwaitConn),
		e2eScion:   mustEnv(t, envE2EScion),
		e2eHTTP:    mustEnv(t, envE2EHTTP),
	}
}

// setup loads the node image, generates the topology and deploys the lab.
func (h *harness) setup(t *testing.T) {
	require.NoError(t, os.MkdirAll(h.genDir, 0o755))

	t.Log("--- setup: loading node image")
	h.run(t, h.workDir, *dockerC, "load", "--input", h.imageTar)

	t.Log("--- setup: generating topology")
	h.run(t, h.workDir, h.testgenBin, "-c", h.topo, "-o", h.genDir, "--name", *labName)
	h.collect(t, h.clabYML, *labName+".clab.yml")

	t.Log("--- setup: deploying containerlab topology")
	h.run(t, h.workDir, *clabC, "deploy", "--reconfigure", "-t", h.clabYML)

	t.Log("--- setup: waiting for connectivity")
	h.run(t, h.workDir, h.awaitConn, "-gen", h.genDir)
}

// execute runs the e2e_scion and e2e_http tests against the deployed lab. The
// output of each driver is captured as an artifact.
func (h *harness) execute(t *testing.T) {
	t.Run("e2e_scion", func(t *testing.T) {
		out := h.run(t, h.workDir, h.e2eScion,
			"--gen", h.genDir,
			"--lab", *labName,
			"--docker", *dockerC,
		)
		h.collectBytes(t, out, "e2e_scion.log")
	})
	t.Run("e2e_http", func(t *testing.T) {
		out := h.run(t, h.workDir, h.e2eHTTP, "run",
			"--gen", h.genDir,
			"--lab", *labName,
			"--docker", *dockerC,
		)
		h.collectBytes(t, out, "e2e_http.log")
	})
}

// teardown destroys the containerlab topology. A missing topology (nothing was
// deployed) is skipped silently; a real destroy failure fails the test but the
// run still completes.
func (h *harness) teardown(t *testing.T) {
	if _, err := os.Stat(h.clabYML); err != nil {
		t.Logf("--- teardown: no clab topology at %s, skipping", h.clabYML)
		return
	}
	t.Log("--- teardown: destroying containerlab topology")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	name, args := splitCmd(*clabC, "destroy", "--cleanup", "-t", h.clabYML)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = h.workDir
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("%s", out)
	}
	if err != nil {
		t.Errorf("clab destroy failed: %s", err)
	}
}

// run executes a command in dir, logging its combined output, and fails the
// test if it exits non-zero. The combined output is returned so callers can
// persist it as an artifact.
func (h *harness) run(t *testing.T, dir, command string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	name, full := splitCmd(command, args...)
	t.Logf("$ %s %v", name, full)
	cmd := exec.CommandContext(ctx, name, full...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("%s", out)
	}
	require.NoError(t, err, "command failed: %s %v", name, full)
	return out
}

// collect copies a file from the work dir into the outputs dir under name, so
// it is gathered as a bazel undeclared output. Best-effort: a missing file or
// no outputs dir is a silent no-op.
func (h *harness) collect(t *testing.T, src, name string) {
	if h.outputsDir == "" {
		return
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Logf("collect %s: %s", name, err)
		return
	}
	h.collectBytes(t, data, name)
}

// collectBytes writes data into the outputs dir under name. Best-effort: no
// outputs dir is a silent no-op.
func (h *harness) collectBytes(t *testing.T, data []byte, name string) {
	if h.outputsDir == "" {
		return
	}
	dst := filepath.Join(h.outputsDir, name)
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Logf("collect %s: %s", name, err)
	}
}

// splitCmd splits a (possibly multi-word) command like "sudo docker" into its
// executable and leading arguments, then appends args.
func splitCmd(command string, args ...string) (name string, argv []string) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return command, args
	}
	return fields[0], append(fields[1:], args...)
}

// workingDir returns the directory the lab is generated and deployed in. It
// must not be TEST_UNDECLARED_OUTPUTS_DIR (see harness.workDir). Priority: the
// -artifacts flag (pinned so phases run in separate bazel invocations share the
// lab), else TEST_TMPDIR/clab (bazel-managed, not validated as outputs), else a
// temp dir.
func workingDir(t *testing.T) string {
	dir := *artifactsFlag
	if dir == "" {
		if tmp := os.Getenv("TEST_TMPDIR"); tmp != "" {
			dir = filepath.Join(tmp, "clab")
		}
	}
	if dir == "" {
		return t.TempDir()
	}
	require.NoError(t, os.MkdirAll(dir, 0o755))
	abs, err := filepath.Abs(dir)
	require.NoError(t, err)
	return abs
}

// mustEnv resolves a bazel-provided artifact path from an environment variable.
// The go_test target sets these to $(rootpath ...) values, which are
// runfiles-root-relative paths, so they must be resolved through the runfiles
// tree rather than against the working directory.
func mustEnv(t *testing.T, name string) string {
	v := os.Getenv(name)
	require.NotEmptyf(t, v, "environment variable %s must be set (run via the bazel target)", name)
	if filepath.IsAbs(v) {
		return v
	}
	abs, err := resolveRunfile(v)
	require.NoErrorf(t, err, "resolving runfiles location for %s=%q", name, v)
	return abs
}

// resolvePath resolves a path that may be a $(rootpath ...) runfiles path, an
// absolute path, or (for a user-supplied override) a path relative to the
// working directory. Absolute paths are returned as-is; runfiles paths are
// resolved through the runfiles tree, falling back to a working-directory
// absolute path when not found there.
func resolvePath(t *testing.T, v string) string {
	if filepath.IsAbs(v) {
		return v
	}
	if abs, err := resolveRunfile(v); err == nil {
		return abs
	}
	abs, err := filepath.Abs(v)
	require.NoErrorf(t, err, "resolving path %q", v)
	return abs
}

// resolveRunfile resolves a $(rootpath ...) value (a runfiles-root-relative
// path) to an absolute filesystem path. $(rootpath) for an external repo emits
// "external/<repo>/..."; rules_go runfiles want "<repo>/...". For the main repo
// it emits a bare path, which must be qualified with the main repo's canonical
// name.
func resolveRunfile(rootpath string) (string, error) {
	if rest, ok := strings.CutPrefix(rootpath, "external/"); ok {
		return runfiles.Rlocation(rest)
	}
	// Main repo: try the canonical Bzlmod name first, then the path as-is for
	// older runfiles layouts.
	if abs, err := runfiles.Rlocation("_main/" + rootpath); err == nil {
		return abs, nil
	}
	return runfiles.Rlocation(rootpath)
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
