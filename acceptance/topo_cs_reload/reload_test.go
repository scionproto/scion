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
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/bazelbuild/rules_go/go/tools/bazel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	genCryptoLocation = flag.String("gen_crypto", "testdata/gen_crypto.sh",
		"Location of the gen_crypto.sh script.")
	scionPKILocation  = flag.String("scion_pki", "", "Location of the scion-pki binary.")
	topoLocation      = flag.String("topo", "", "Location of the topolgy file.")
	cryptoLibLocation = flag.String("crypto_lib", "", "Location of the cryptolib.")
)

func TestPSTopoReload(t *testing.T) {
	s := setupTest(t)
	defer s.teardownTest(t)

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
		"/topology_invalid_changed_ip.json",
		"/topology_invalid_changed_port.json",
	}
	for _, invalidFile := range invalidFiles {
		t.Run(fmt.Sprintf("file %s", invalidFile), func(t *testing.T) {
			t.Logf("loading %s", invalidFile)
			s.loadTopo(t, invalidFile)
			checkTopology(t, origTopo)
		})
	}

	// now try to load a valid one.
	t.Run("valid", func(t *testing.T) {
		s.loadTopo(t, "/topology_reload.json")
		checkTopology(t, reloadTopo)
	})
}

type testState struct {
	extraEnv     []string
	extraCleanup []func()
}

func setupTest(t *testing.T) testState {
	tmpDir, clean := xtest.MustTempDir("", "topo_cs_reload")
	s := testState{
		extraEnv:     []string{"TOPO_CS_RELOAD_CONFIG_DIR=" + tmpDir},
		extraCleanup: []func(){clean},
	}
	scionPKI, err := bazel.Runfile(*scionPKILocation)
	require.NoError(t, err)
	cryptoLib, err := bazel.Runfile(*cryptoLibLocation)
	require.NoError(t, err)
	topoFile, err := bazel.Runfile(*topoLocation)
	require.NoError(t, err)
	s.mustExec(t, *genCryptoLocation, scionPKI,
		"crypto.tar", topoFile, cryptoLib)
	s.mustExec(t, "tar", "-xf", "crypto.tar", "-C", tmpDir)
	// first load the docker images from bazel into the docker deamon, the
	// tars are in the same folder as this test runs in bazel.
	s.mustExec(t, "docker", "image", "load", "-i", "dispatcher.tar")
	s.mustExec(t, "docker", "image", "load", "-i", "control.tar")
	// now start the docker containers
	s.mustExec(t, "docker-compose", "-f", "docker-compose.yml", "up", "-d")
	// wait a bit to make sure the containers are ready.
	time.Sleep(time.Second / 2)
	t.Log("Test setup done")
	s.mustExec(t, "docker-compose", "-f", "docker-compose.yml", "ps")
	return s
}

func (s testState) teardownTest(t *testing.T) {
	defer s.mustExec(t, "docker-compose", "-f", "docker-compose.yml", "down", "-v")

	outdir, exists := os.LookupEnv("TEST_UNDECLARED_OUTPUTS_DIR")
	require.True(t, exists, "TEST_UNDECLARED_OUTPUTS_DIR must be defined")
	require.NoError(t, os.MkdirAll(fmt.Sprintf("%s/logs", outdir), os.ModePerm|os.ModeDir))
	// collect logs
	for service, file := range map[string]string{
		"topo_cs_reload_dispatcher":  "disp.log",
		"topo_cs_reload_control_srv": "control.log",
	} {
		cmd := exec.Command("docker-compose", "-f", "docker-compose.yml", "logs", "--no-color",
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
	s.Cleanup()
}

func (s testState) loadTopo(t *testing.T, name string) {
	t.Helper()

	s.mustExec(t, "docker-compose", "-f", "docker-compose.yml", "exec", "-T",
		"topo_cs_reload_control_srv", "mv", name, "/topology.json")
	s.mustExec(t, "docker-compose", "-f", "docker-compose.yml", "kill", "-s", "SIGHUP",
		"topo_cs_reload_control_srv")
}

func (s testState) mustExec(t *testing.T, name string, arg ...string) {
	t.Helper()

	cmd := exec.Command(name, arg...)
	cmd.Env = append(os.Environ(), s.extraEnv...)
	output, err := cmd.CombinedOutput()
	t.Logf("%s %v\n%s\n", name, arg, string(output))
	require.NoError(t, err, "Failed to run %s %v: %v\n%s", name, arg, err, string(output))
}

func (s testState) Cleanup() {
	for _, c := range s.extraCleanup {
		c()
	}
}

func checkTopology(t *testing.T, expectedTopo *topology.RWTopology) {
	t.Helper()

	eJSON, err := json.Marshal(expectedTopo)
	require.NoError(t, err)
	actualTopo := fetchTopologyFromEndpoint(t, "http://242.253.100.2:30453/topology")
	aJSON, err := json.Marshal(actualTopo)
	require.NoError(t, err)
	assert.Equal(t, eJSON, aJSON)
}

func fetchTopologyFromEndpoint(t *testing.T, url string) *topology.RWTopology {
	t.Helper()

	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	var topo *topology.RWTopology
	require.NoError(t, json.Unmarshal(body, &topo))
	return topo
}
