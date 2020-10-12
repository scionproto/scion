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

package brconf_test

import (
	"bytes"
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/log/logtest"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/router/brconf"
)

func TestLoad(t *testing.T) {
	tests := map[string]struct {
		ExpectedTopo func(t *testing.T) topology.Topology
	}{
		"base": {
			ExpectedTopo: func(t *testing.T) topology.Topology {
				expectedTopo, err := topology.FromJSONFile("testdata/topology.json")
				require.NoError(t, err)
				return expectedTopo
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c, err := brconf.Load("br1-ff00_0_110-2", "testdata")
			assert.NoError(t, err)
			assert.NotNil(t, c)
			expectedTopo := test.ExpectedTopo(t)
			assert.Equal(t, expectedTopo, c.Topo)
		})
	}
}

func TestConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg brconf.Config
	cfg.Sample(&sample, nil, nil)

	InitTestConfig(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).Strict(true).Decode(&cfg)
	assert.NoError(t, err)
	CheckTestConfig(t, &cfg, brconf.IDSample)
}

func InitTestConfig(cfg *brconf.Config) {
	envtest.InitTest(&cfg.General, &cfg.Metrics, nil, nil)
	logtest.InitTestLogging(&cfg.Logging)
}

func CheckTestConfig(t *testing.T, cfg *brconf.Config, id string) {
	envtest.CheckTest(t, &cfg.General, &cfg.Metrics, nil, nil, id)
	logtest.CheckTestLogging(t, &cfg.Logging, id)
}
