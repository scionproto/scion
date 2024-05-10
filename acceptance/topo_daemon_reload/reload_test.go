// Copyright 2019 Anapaya Systems
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

package reload_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/private/topology"
)

func TestSDTopoReload(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("TEST_TARGET"), "go_default_test") {
		t.Skip("This test only runs as bazel unit test")
	}

	setupTest(t)
	defer collectLogs(t)

	// first load the topo files to memory for comparison.
	origTopo, err := topology.RWTopologyFromJSONFile("../topo_common/topology.json")
	assert.NoError(t, err, "Loading origTopo failed")
	reloadTopo, err := topology.RWTopologyFromJSONFile("testdata/topology_reload.json")
	assert.NoError(t, err, "Loading reloadTopo failed")

	// check initial topo matches expected.
	checkTopology(t, origTopo)

	// try invalid topos first.
	invalidFiles := []string{
		"/topology_invalid_ia.json",
		"/topology_invalid_attributes.json",
		"/topology_invalid_mtu.json",
	}
	for _, invalidFile := range invalidFiles {
		t.Logf("loading %s", invalidFile)
		loadTopo(t, invalidFile)
		checkTopology(t, origTopo)
	}

	// now try to load a valid one.
	loadTopo(t, "/topology_reload.json")
	checkTopology(t, reloadTopo)
}

func setupTest(t *testing.T) {
	// first load the docker images from bazel into the docker deamon, the
	// tars are in the same folder as this test runs in bazel.
	mustExec(t, "docker", "image", "load", "-i", "daemon.tar/tarball.tar")
	t.Cleanup(func() {
		mustExec(t, "docker", "image", "rm", "scion/acceptance/topo_daemon_reload:daemon")
	})
	// now start the docker containers
	mustExec(t, "docker", "compose", "-f", "docker-compose.yml",
		"up", "-d", "topo_daemon_reload_daemon")
	t.Cleanup(func() { mustExec(t, "docker", "compose", "-f", "docker-compose.yml", "down", "-v") })
	// wait a bit to make sure the containers are ready.
	time.Sleep(time.Second / 2)
	t.Log("Test setup done")
	mustExec(t, "docker", "compose", "-f", "docker-compose.yml", "ps")
}

func collectLogs(t *testing.T) {
	outdir, exists := os.LookupEnv("TEST_UNDECLARED_OUTPUTS_DIR")
	require.True(t, exists, "TEST_UNDECLARED_OUTPUTS_DIR must be defined")
	require.NoError(t, os.MkdirAll(fmt.Sprintf("%s/logs", outdir), os.ModePerm|os.ModeDir))
	// collect logs
	for service, file := range map[string]string{
		"topo_daemon_reload_daemon": "daemon.log",
	} {
		cmd := exec.Command("docker", "compose",
			"-f", "docker-compose.yml", "logs", "--no-color",
			service)
		logFileName := fmt.Sprintf("%s/logs/%s", outdir, file)
		logFile, err := os.Create(logFileName)
		if err != nil {
			t.Logf("Failed to create logfile %s for %s", logFileName, service)
			continue
		}
		cmd.Stdout = logFile
		if err = cmd.Run(); err != nil {
			t.Logf("Failed to read log for service %s: %v\n", service, err)
		}
	}
}

func loadTopo(t *testing.T, name string) {
	t.Helper()

	mustExec(t, "docker", "compose", "-f", "docker-compose.yml",
		"exec", "-T", "topo_daemon_reload_daemon", "mv", name, "/topology.json")
	mustExec(t, "docker", "compose", "-f", "docker-compose.yml",
		"kill", "-s", "SIGHUP", "topo_daemon_reload_daemon")
}

func mustExec(t *testing.T, name string, arg ...string) {
	t.Helper()

	cmd := exec.Command(name, arg...)
	output, err := cmd.Output()
	t.Logf("%s %v\n%s\n", name, arg, string(output))
	require.NoError(t, err, "Failed to run %s %v: %v\n%s", name, arg, err, string(output))
}

func checkTopology(t *testing.T, expectedTopo *topology.RWTopology) {
	t.Helper()

	eJSON, err := json.Marshal(expectedTopo)
	require.NoError(t, err)
	actualTopo := fetchTopologyFromEndpoint(t, "http://242.254.100.2:30455/topology")
	aJSON, err := json.Marshal(actualTopo)
	require.NoError(t, err)
	assert.Equal(t, eJSON, aJSON)
}

func fetchTopologyFromEndpoint(t *testing.T, url string) *topology.RWTopology {
	t.Helper()

	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var topo *topology.RWTopology
	require.NoError(t, json.Unmarshal(body, &topo))
	return topo
}
