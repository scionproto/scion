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
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/topology"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestPSTopoReloadSuite struct {
	suite.Suite
	origTopo   *topology.RWTopology
	reloadTopo *topology.RWTopology
}

func (s *TestPSTopoReloadSuite) SetupTest() {
	// first load the docker images from bazel into the docker deamon.
	s.exec("dispatcher")
	s.exec("path_srv")
	s.exec("docker-compose", "-f", "docker-compose.yml", "up",
		"-d", "topo_ps_reload_dispatcher", "topo_ps_reload_path_srv")
	var err error
	s.origTopo, err = topology.RWTopologyFromJSONFile("testdata/topology.json")
	s.Require().NoError(err, "Loading origTopo failed")
	s.reloadTopo, err = topology.RWTopologyFromJSONFile("testdata/topology_reload.json")
	s.Require().NoError(err, "Loading reloadTopo failed")
	time.Sleep(time.Second)
}

func (s *TestPSTopoReloadSuite) TearDownTest() {
	outdir, exists := os.LookupEnv("TEST_UNDECLARED_OUTPUTS_DIR")
	s.Require().True(exists, "TEST_UNDECLARED_OUTPUTS_DIR must be defined")
	s.Require().NoError(os.MkdirAll(fmt.Sprintf("%s/logs", outdir), os.ModePerm|os.ModeDir))
	// collect logs
	for _, file := range []string{"disp_1-ff00_0_110.log", "ps1-ff00_0_110-1.log"} {
		cmd := exec.Command("docker-compose", "-f", "docker-compose.yml", "run", "-T",
			"topo_ps_reload_log_exporter", "cat", fmt.Sprintf("/share/logs/%s", file))
		output, err := cmd.Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to collect log file %s: %v\n", file, err)
		}
		fmt.Printf("Writing file: %s", fmt.Sprintf("%s/logs/%s\n", outdir, file))
		err = ioutil.WriteFile(fmt.Sprintf("%s/logs/%s", outdir, file), output, os.ModePerm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write log file %s: %v\n", file, err)
		}
	}
	s.exec("docker-compose", "-f", "docker-compose.yml", "down", "-v")
}

func (s *TestPSTopoReloadSuite) TestReload() {
	checkTopology(s.T(), s.origTopo)
	s.exec("docker-compose", "-f", "docker-compose.yml", "exec", "-T",
		"topo_ps_reload_path_srv", "mv", "/topology_reload.json", "/topology.json")
	s.exec("docker-compose", "-f", "docker-compose.yml", "kill", "-s", "SIGHUP",
		"topo_ps_reload_path_srv")
	checkTopology(s.T(), s.reloadTopo)
}

func (s *TestPSTopoReloadSuite) exec(name string, arg ...string) {
	cmd := exec.Command(name, arg...)
	output, err := cmd.Output()
	s.T().Log(string(output))
	s.Require().NoError(err, "Failed to run %s %v: %v\n%s", name, arg, err, string(output))
}

func TestPSTopoReload(t *testing.T) {
	suite.Run(t, new(TestPSTopoReloadSuite))
}

func checkTopology(t *testing.T, expectedTopo *topology.RWTopology) {
	eJSON, err := json.Marshal(expectedTopo)
	require.NoError(t, err)
	actualTopo := fetchTopologyFromEndpoint(t, "http://242.253.100.2:30453/topology")
	aJSON, err := json.Marshal(actualTopo)
	require.NoError(t, err)
	assert.Equal(t, eJSON, aJSON)
}

func fetchTopologyFromEndpoint(t *testing.T, url string) *topology.RWTopology {
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	var topo *topology.RWTopology
	require.NoError(t, json.Unmarshal(body, &topo))
	return topo
}
