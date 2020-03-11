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

package sigconfig

import (
	"bytes"
	"net"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/log/logtest"
	"github.com/scionproto/scion/go/lib/xtest"
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
	envtest.InitTest(nil, &cfg.Metrics, nil, &cfg.Sciond)
	logtest.InitTestLogging(&cfg.Logging)
	InitTestSigConf(&cfg.Sig)
}

func InitTestSigConf(cfg *SigConf) {

}

func CheckTestConfig(t *testing.T, cfg *Config, id string) {
	envtest.CheckTest(t, nil, &cfg.Metrics, nil, &cfg.Sciond, id)
	logtest.CheckTestLogging(t, &cfg.Logging, id)
	CheckTestSigConf(t, &cfg.Sig, id)
}

func CheckTestSigConf(t *testing.T, cfg *SigConf, id string) {
	assert.Equal(t, "sig4", cfg.ID)
	assert.Equal(t, "/etc/scion/sig/sig.json", cfg.SIGConfig)
	assert.Equal(t, xtest.MustParseIA("1-ff00:0:113"), cfg.IA)
	assert.Equal(t, net.ParseIP("192.0.2.100"), cfg.IP)
	assert.Equal(t, DefaultCtrlPort, int(cfg.CtrlPort))
	assert.Equal(t, DefaultEncapPort, int(cfg.EncapPort))
	assert.Equal(t, DefaultTunName, cfg.Tun)
	assert.Equal(t, DefaultTunRTableId, cfg.TunRTableId)
}
