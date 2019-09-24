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
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery/idiscoverytest"
	"github.com/scionproto/scion/go/lib/truststorage/truststoragetest"
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

func TestConfig_InitDefaults(t *testing.T) {
	t.Run("Load Conf", func(t *testing.T) {
		var cfg Config
		_, err := toml.DecodeFile("testdata/cs.toml", &cfg)
		assert.NoError(t, err)

		cfg.InitDefaults()
		assert.Equal(t, 7*time.Hour, cfg.CS.LeafReissueLeadTime.Duration)
		assert.Equal(t, 48*time.Hour, cfg.CS.IssuerReissueLeadTime.Duration)
		assert.Equal(t, 12*time.Second, cfg.CS.ReissueRate.Duration)
		assert.Equal(t, 6*time.Second, cfg.CS.ReissueTimeout.Duration)
		assert.True(t, cfg.CS.AutomaticRenewal)
		assert.True(t, cfg.CS.DisableCorePush)
	})

	t.Run("Load Default", func(t *testing.T) {
		var cfg Config
		_, err := toml.DecodeReader(strings.NewReader("[cs]"), &cfg)
		assert.NoError(t, err)

		cfg.InitDefaults()
		assert.Equal(t, LeafReissTime, cfg.CS.LeafReissueLeadTime.Duration)
		assert.Equal(t, IssuerReissTime, cfg.CS.IssuerReissueLeadTime.Duration)
		assert.Equal(t, ReissReqRate, cfg.CS.ReissueRate.Duration)
		assert.Equal(t, ReissueReqTimeout, cfg.CS.ReissueTimeout.Duration)
		assert.False(t, cfg.CS.AutomaticRenewal)
		assert.False(t, cfg.CS.DisableCorePush)
	})
}

func InitTestConfig(cfg *Config) {
	envtest.InitTest(&cfg.General, &cfg.Logging, &cfg.Metrics, &cfg.Tracing, &cfg.Sciond)
	truststoragetest.InitTestConfig(&cfg.TrustDB)
	idiscoverytest.InitTestConfig(&cfg.Discovery)
	InitTestCSConfig(&cfg.CS)
}

func InitTestCSConfig(cfg *CSConfig) {
	cfg.AutomaticRenewal = true
	cfg.DisableCorePush = true
}

func CheckTestConfig(t *testing.T, cfg *Config, id string) {
	envtest.CheckTest(t, &cfg.General, &cfg.Logging, &cfg.Metrics, &cfg.Tracing, &cfg.Sciond, id)
	truststoragetest.CheckTestConfig(t, &cfg.TrustDB, id)
	idiscoverytest.CheckTestConfig(t, &cfg.Discovery)
	CheckTestCSConfig(t, &cfg.CS)
}

func CheckTestCSConfig(t *testing.T, cfg *CSConfig) {
	assert.Equal(t, ReissReqRate, cfg.ReissueRate.Duration)
	assert.Equal(t, ReissueReqTimeout, cfg.ReissueTimeout.Duration)
	assert.False(t, cfg.AutomaticRenewal)
	assert.Equal(t, LeafReissTime, cfg.LeafReissueLeadTime.Duration)
	assert.Equal(t, IssuerReissTime, cfg.IssuerReissueLeadTime.Duration)
	assert.False(t, cfg.DisableCorePush)
}
