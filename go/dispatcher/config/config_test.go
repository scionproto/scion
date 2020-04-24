// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package config

import (
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/log/logtest"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/topology"
)

func TestConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg Config
	cfg.Sample(&sample, nil, nil)

	InitTestConfig(&cfg)
	meta, err := toml.Decode(sample.String(), &cfg)
	assert.NoError(t, err)
	assert.Empty(t, meta.Undecoded())
	CheckTestConfig(t, &cfg, idSample)
}

func InitTestConfig(cfg *Config) {
	envtest.InitTest(nil, &cfg.Metrics, nil, nil)
	logtest.InitTestLogging(&cfg.Logging)
	cfg.Dispatcher.DeleteSocket = true
}

func CheckTestConfig(t *testing.T, cfg *Config, id string) {
	envtest.CheckTest(t, nil, &cfg.Metrics, nil, nil, id)
	logtest.CheckTestLogging(t, &cfg.Logging, id)
	assert.Equal(t, id, cfg.Dispatcher.ID)
	assert.Equal(t, reliable.DefaultDispPath, cfg.Dispatcher.ApplicationSocket)
	assert.Equal(t, reliable.DefaultDispSocketFileMode, int(cfg.Dispatcher.SocketFileMode))
	assert.Equal(t, topology.EndhostPort, cfg.Dispatcher.UnderlayPort)
	assert.False(t, cfg.Dispatcher.DeleteSocket)
}
