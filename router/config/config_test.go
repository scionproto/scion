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

package config_test

import (
	"bytes"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/log/logtest"
	"github.com/scionproto/scion/private/env/envtest"
	apitest "github.com/scionproto/scion/private/mgmtapi/mgmtapitest"
	"github.com/scionproto/scion/router/config"
)

func TestConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg config.Config
	cfg.Sample(&sample, nil, nil)

	InitTestConfig(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).DisallowUnknownFields().Decode(&cfg)
	assert.NoError(t, err)
	CheckTestConfig(t, &cfg, config.IDSample)
}

func InitTestConfig(cfg *config.Config) {
	apitest.InitConfig(&cfg.API)
	envtest.InitTest(&cfg.General, &cfg.Metrics, nil, nil)
	logtest.InitTestLogging(&cfg.Logging)
}

func CheckTestConfig(t *testing.T, cfg *config.Config, id string) {
	apitest.CheckConfig(t, &cfg.API)
	envtest.CheckTest(t, &cfg.General, &cfg.Metrics, nil, nil, id)
	logtest.CheckTestLogging(t, &cfg.Logging, id)
}
