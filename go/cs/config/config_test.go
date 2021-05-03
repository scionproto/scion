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

package config

import (
	"bytes"
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/log/logtest"
	"github.com/scionproto/scion/go/pkg/api/apitest"
	"github.com/scionproto/scion/go/pkg/api/jwtauth"
	storagetest "github.com/scionproto/scion/go/pkg/storage/test"
)

func TestConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg Config
	cfg.Sample(&sample, nil, nil)

	InitTestConfig(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).Strict(true).Decode(&cfg)
	assert.NoError(t, err)
	CheckTestConfig(t, &cfg, idSample)
}

func InitTestConfig(cfg *Config) {
	apitest.InitConfig(&cfg.API)
	envtest.InitTest(&cfg.General, &cfg.Metrics, &cfg.Tracing, nil)
	logtest.InitTestLogging(&cfg.Logging)
	InitTestBSConfig(&cfg.BS)
	InitTestCA(&cfg.CA)
}

func InitTestBSConfig(cfg *BSConfig) {
	InitTestPolicies(&cfg.Policies)
}

func InitTestPolicies(cfg *Policies) {
	cfg.Propagation = "test"
	cfg.CoreRegistration = "test"
	cfg.UpRegistration = "test"
	cfg.DownRegistration = "test"
}

func CheckTestConfig(t *testing.T, cfg *Config, id string) {
	apitest.CheckConfig(t, &cfg.API)
	envtest.CheckTest(t, &cfg.General, &cfg.Metrics, &cfg.Tracing, nil, id)
	logtest.CheckTestLogging(t, &cfg.Logging, id)
	storagetest.CheckTestTrustDBConfig(t, &cfg.TrustDB, id)
	storagetest.CheckTestBeaconDBConfig(t, &cfg.BeaconDB, id)
	storagetest.CheckTestPathDBConfig(t, &cfg.PathDB, id)
	storagetest.CheckTestRenewalDBConfig(t, &cfg.RenewalDB, id)
	CheckTestBSConfig(t, &cfg.BS)
	CheckTestPSConfig(t, &cfg.PS, id)
	CheckTestCA(t, &cfg.CA)
}

func CheckTestBSConfig(t *testing.T, cfg *BSConfig) {
	assert.Equal(t, DefaultOriginationInterval, cfg.OriginationInterval.Duration)
	assert.Equal(t, DefaultPropagationInterval, cfg.PropagationInterval.Duration)
	assert.Equal(t, DefaultRegistrationInterval, cfg.RegistrationInterval.Duration)
	CheckTestPolicies(t, &cfg.Policies)
}

func CheckTestPolicies(t *testing.T, cfg *Policies) {
	assert.Empty(t, cfg.Propagation)
	assert.Empty(t, cfg.CoreRegistration)
	assert.Empty(t, cfg.UpRegistration)
	assert.Empty(t, cfg.DownRegistration)
}

func InitTestPSConfig(cfg *PSConfig) {
	cfg.HiddenPathsCfg = "garbage"
}

func CheckTestPSConfig(t *testing.T, cfg *PSConfig, id string) {
	assert.Equal(t, DefaultQueryInterval, cfg.QueryInterval.Duration)
	assert.Empty(t, cfg.HiddenPathsCfg)
}

func InitTestCA(cfg *CA) {
	cfg.DisableLegacyRequest = true
}

func CheckTestCA(t *testing.T, cfg *CA) {
	assert.Equal(t, DefaultMaxASValidity, cfg.MaxASValidity.Duration)
	assert.Equal(t, cfg.DisableLegacyRequest, false)
	assert.Equal(t, cfg.Mode, InProcess)
	CheckTestService(t, &cfg.Service)
}

func CheckTestService(t *testing.T, cfg *CAService) {
	assert.Empty(t, cfg.SharedSecret)
	assert.Empty(t, cfg.Address)
	assert.Equal(t, jwtauth.DefaultTokenLifetime, cfg.Lifetime.Duration)
	assert.Empty(t, cfg.ClientID)
}
