// Copyright 2020 Anapaya Systems
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

	toml "github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/gateway/config"
	"github.com/scionproto/scion/gateway/config/configtest"
	"github.com/scionproto/scion/pkg/log/logtest"
	"github.com/scionproto/scion/private/env/envtest"
	apitest "github.com/scionproto/scion/private/mgmtapi/mgmtapitest"
)

func TestConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg config.Config
	cfg.Sample(&sample, nil, nil)

	InitConfig(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).DisallowUnknownFields().Decode(&cfg)
	assert.NoError(t, err)
	CheckConfig(t, &cfg)
}

func InitConfig(cfg *config.Config) {
	envtest.InitTest(nil, &cfg.Metrics, nil, &cfg.Daemon)
	logtest.InitTestLogging(&cfg.Logging)
	apitest.InitConfig(&cfg.API)
	configtest.InitGateway(&cfg.Gateway)
	configtest.InitTunnel(&cfg.Tunnel)
}

func CheckConfig(t *testing.T, cfg *config.Config) {
	envtest.CheckTest(t, nil, &cfg.Metrics, nil, &cfg.Daemon, "gateway")
	logtest.CheckTestLogging(t, &cfg.Logging, "gateway")
	configtest.CheckGateway(t, &cfg.Gateway)
	apitest.CheckConfig(t, &cfg.API)
	configtest.CheckTunnel(t, &cfg.Tunnel)
}
