// Copyright 2026 ETH Zurich
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
	"fmt"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/log/logtest"
	"github.com/scionproto/scion/pkg/private/util"
)

func TestConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg Config
	cfg.Sample(&sample, nil, nil)

	InitTestConfig(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).DisallowUnknownFields().Decode(&cfg)
	assert.NoError(t, err, "config: \n%s", sample.String())
	CheckTestConfig(t, &cfg, idSample)
}

func InitTestConfig(cfg *Config) {
	logtest.InitTestLogging(&cfg.Logging)
	InitTestHBConfig(&cfg.HB)
}

func InitTestHBConfig(cfg *HBConfig) {
	InitDefaults(cfg)
}

func InitDefaults(cfg *HBConfig) {
	resD := util.DurWrap{}
	_ = resD.Set(fmt.Sprintf("%vs", DefaultReservationDuration))
	cfg.ReservationDuration = resD
}

func CheckTestConfig(t *testing.T, cfg *Config, id string) {
	CheckTestHBConfig(t, &cfg.HB)
}

func CheckTestHBConfig(t *testing.T, cfg *HBConfig) {
	assert.Equal(t, DefaultReservationDuration, cfg.ReservationDuration.Duration)
}
