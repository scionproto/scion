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

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/log/logtest"
	"github.com/scionproto/scion/private/env/envtest"
	apitest "github.com/scionproto/scion/private/mgmtapi/mgmtapitest"
)

func TestConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg Config
	cfg.Sample(&sample, nil, nil)

	InitTestConfig(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).DisallowUnknownFields().Decode(&cfg)
	assert.NoError(t, err)
	CheckTestConfig(t, &cfg, idSample)
}

func InitTestConfig(cfg *Config) {
	apitest.InitConfig(&cfg.API)
	envtest.InitTest(nil, &cfg.Metrics, nil, nil)
	logtest.InitTestLogging(&cfg.Logging)
	cfg.Dispatcher.InitDefaults()
}

func CheckTestConfig(t *testing.T, cfg *Config, id string) {
	apitest.CheckConfig(t, &cfg.API)
	envtest.CheckTest(t, nil, &cfg.Metrics, nil, nil, id)
	logtest.CheckTestLogging(t, &cfg.Logging, id)
	assert.Equal(t, id, cfg.Dispatcher.ID)
	assert.True(t, cfg.Dispatcher.UnderlayAddr.IsValid())
	assert.Len(t, cfg.Dispatcher.ServiceAddresses, 6)
}
