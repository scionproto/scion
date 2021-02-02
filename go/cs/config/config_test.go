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
	"time"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/log/logtest"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/api/apitest"
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

func TestInvalidTTL(t *testing.T) {
	cfg := BSConfig{}
	cfg.InitDefaults()
	err := cfg.Validate()
	assert.NoError(t, err)
	cfg.RevOverlap = util.DurWrap{Duration: cfg.RevTTL.Duration + time.Second}
	err = cfg.Validate()
	assert.Error(t, err)
	cfg.InitDefaults()
	cfg.RevTTL = util.DurWrap{Duration: path_mgmt.MinRevTTL - time.Second}
	err = cfg.Validate()
	assert.Error(t, err)
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
	CheckTestCA(t, &cfg.CA, id)
}

func CheckTestBSConfig(t *testing.T, cfg *BSConfig) {
	assert.Equal(t, DefaultKeepaliveTimeout, cfg.KeepaliveTimeout.Duration)
	assert.Equal(t, DefaultKeepaliveInterval, cfg.KeepaliveInterval.Duration)
	assert.Equal(t, DefaultOriginationInterval, cfg.OriginationInterval.Duration)
	assert.Equal(t, DefaultPropagationInterval, cfg.PropagationInterval.Duration)
	assert.Equal(t, DefaultRegistrationInterval, cfg.RegistrationInterval.Duration)
	assert.Equal(t, DefaultExpiredCheckInterval, cfg.ExpiredCheckInterval.Duration)
	assert.Equal(t, DefaultRevTTL, cfg.RevTTL.Duration)
	assert.Equal(t, DefaultRevOverlap, cfg.RevOverlap.Duration)
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

func InitTestCA(cfg *CA) {}

func CheckTestCA(t *testing.T, cfg *CA, id string) {
	assert.Equal(t, DefaultMaxASValidity, cfg.MaxASValidity.Duration)
}
