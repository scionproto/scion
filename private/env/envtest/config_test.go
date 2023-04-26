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

package envtest

import (
	"bytes"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
)

func TestGeneralSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg env.General
	cfg.Sample(&sample, nil, map[string]string{config.ID: "general"})
	InitTestGeneral(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).DisallowUnknownFields().Decode(&cfg)
	assert.NoError(t, err)
	CheckTestGeneral(t, &cfg, "general")
}

func TestMetricsSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg env.Metrics
	cfg.Sample(&sample, nil, nil)
	InitTestMetrics(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).DisallowUnknownFields().Decode(&cfg)
	assert.NoError(t, err)
	CheckTestMetrics(t, &cfg)
}

func TestTracingSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg env.Tracing
	cfg.Sample(&sample, nil, nil)
	InitTestTracing(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).DisallowUnknownFields().Decode(&cfg)
	assert.NoError(t, err)
	CheckTestTracing(t, &cfg)
}

func TestSCIONDClientSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg env.Daemon
	cfg.Sample(&sample, nil, nil)
	InitTestSCIOND(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).DisallowUnknownFields().Decode(&cfg)
	assert.NoError(t, err)
	InitTestSCIOND(&cfg)
}
