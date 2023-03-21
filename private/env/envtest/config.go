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
	"net"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/uber/jaeger-client-go"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/private/env"
)

func InitTest(general *env.General, metrics *env.Metrics,
	tracing *env.Tracing, d *env.Daemon) {

	if general != nil {
		InitTestGeneral(general)
	}
	if metrics != nil {
		InitTestMetrics(metrics)
	}
	if tracing != nil {
		InitTestTracing(tracing)
	}
	if d != nil {
		InitTestSCIOND(d)
	}
}

func InitTestGeneral(cfg *env.General) {}
func InitTestMetrics(cfg *env.Metrics) {}

func InitTestTracing(cfg *env.Tracing) {
	cfg.Enabled = true
	cfg.Debug = true
}

func InitTestSCIOND(cfg *env.Daemon) {
	cfg.Address = "garbage"
}

func CheckTest(t *testing.T, general *env.General, metrics *env.Metrics,
	tracing *env.Tracing, d *env.Daemon, id string) {

	if general != nil {
		CheckTestGeneral(t, general, id)
	}
	if metrics != nil {
		CheckTestMetrics(t, metrics)
	}
	if tracing != nil {
		CheckTestTracing(t, tracing)
	}
	if d != nil {
		CheckTestSciond(t, d, id)
	}
}

func CheckTestGeneral(t *testing.T, cfg *env.General, id string) {
	assert.Equal(t, id, cfg.ID)
	assert.Equal(t, "/etc/scion", cfg.ConfigDir)
	assert.Equal(t, filepath.Join(cfg.ConfigDir, env.TopologyFile), cfg.Topology())
}

func CheckTestMetrics(t *testing.T, cfg *env.Metrics) {
	assert.Empty(t, cfg.Prometheus)
}

func CheckTestTracing(t *testing.T, cfg *env.Tracing) {
	assert.False(t, cfg.Enabled)
	assert.False(t, cfg.Debug)
	assert.Equal(
		t,
		net.JoinHostPort(
			jaeger.DefaultUDPSpanServerHost,
			strconv.Itoa(jaeger.DefaultUDPSpanServerPort),
		),
		cfg.Agent,
	)
}

func CheckTestSciond(t *testing.T, cfg *env.Daemon, id string) {
	assert.Equal(t, daemon.DefaultAPIAddress, cfg.Address)
	assert.Equal(t, env.SciondInitConnectPeriod, cfg.InitialConnectPeriod.Duration)
}
