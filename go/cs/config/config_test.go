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

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/cs/beaconstorage/beaconstoragetest"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/log/logtest"
	"github.com/scionproto/scion/go/lib/pathstorage/pathstoragetest"
	"github.com/scionproto/scion/go/lib/truststorage/truststoragetest"
	"github.com/scionproto/scion/go/lib/util"
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
	envtest.InitTest(&cfg.General, &cfg.Metrics, &cfg.Tracing, nil)
	logtest.InitTestLogging(&cfg.Logging)
	truststoragetest.InitTestConfig(&cfg.TrustDB)
	beaconstoragetest.InitTestBeaconDBConf(&cfg.BeaconDB)
	pathstoragetest.InitTestPathDBConf(&cfg.PathDB)
	InitTestBSConfig(&cfg.BS)
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
	envtest.CheckTest(t, &cfg.General, &cfg.Metrics, &cfg.Tracing, nil, id)
	logtest.CheckTestLogging(t, &cfg.Logging, id)
	truststoragetest.CheckTestConfig(t, &cfg.TrustDB, id)
	beaconstoragetest.CheckTestBeaconDBConf(t, &cfg.BeaconDB, id)
	pathstoragetest.CheckTestPathDBConf(t, &cfg.PathDB, id)
	CheckTestBSConfig(t, &cfg.BS)
	CheckTestPSConfig(t, &cfg.PS, id)
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
}

func CheckTestPSConfig(t *testing.T, cfg *PSConfig, id string) {
	assert.Equal(t, DefaultQueryInterval, cfg.QueryInterval.Duration)
}
