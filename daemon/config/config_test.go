// Copyright 2018 Anapaya Systems
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

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log/logtest"
	"github.com/scionproto/scion/private/env/envtest"
	apitest "github.com/scionproto/scion/private/mgmtapi/mgmtapitest"
	storagetest "github.com/scionproto/scion/private/storage/test"
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
	envtest.InitTest(&cfg.General, &cfg.Metrics, &cfg.Tracing, nil)
	logtest.InitTestLogging(&cfg.Logging)
	apitest.InitConfig(&cfg.API)
	InitTestSDConfig(&cfg.SD)
}

func InitTestSDConfig(cfg *SDConfig) {
	cfg.Address = "garbage"
	cfg.DisableSegVerification = true
}

func CheckTestConfig(t *testing.T, cfg *Config, id string) {
	envtest.CheckTest(t, &cfg.General, &cfg.Metrics, &cfg.Tracing, nil, id)
	logtest.CheckTestLogging(t, &cfg.Logging, id)
	storagetest.CheckTestTrustDBConfig(t, &cfg.TrustDB, id)
	storagetest.CheckTestPathDBConfig(t, &cfg.PathDB, id)
	apitest.CheckConfig(t, &cfg.API)
	CheckTestSDConfig(t, &cfg.SD, id)
}

func CheckTestSDConfig(t *testing.T, cfg *SDConfig, id string) {
	assert.Equal(t, daemon.DefaultAPIAddress, cfg.Address)
	assert.False(t, cfg.DisableSegVerification)
	assert.Equal(t, DefaultQueryInterval, cfg.QueryInterval.Duration)
}
