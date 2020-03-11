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

package brconf

import (
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/log/logtest"
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
	envtest.InitTest(&cfg.General, &cfg.Metrics, nil, nil)
	logtest.InitTestLogging(&cfg.Logging)
	InitTestBRConfig(&cfg.BR)
}

func InitTestBRConfig(cfg *BR) {
}

func CheckTestConfig(t *testing.T, cfg *Config, id string) {
	envtest.CheckTest(t, &cfg.General, &cfg.Metrics, nil, nil, id)
	logtest.CheckTestLogging(t, &cfg.Logging, id)
	CheckTestBRConfig(t, &cfg.BR)
}

func CheckTestBRConfig(t *testing.T, cfg *BR) {
	assert.Equal(t, FailActionFatal, cfg.RollbackFailAction)
}
