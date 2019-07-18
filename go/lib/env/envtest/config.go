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
	"fmt"
	"path/filepath"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/uber/jaeger-client-go"

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
)

func InitTest(general *env.General, logging *env.Logging,
	metrics *env.Metrics, tracing *env.Tracing, sciond *env.SciondClient) {
	if general != nil {
		InitTestGeneral(general)
	}
	if logging != nil {
		InitTestLogging(logging)
	}
	if metrics != nil {
		InitTestMetrics(metrics)
	}
	if tracing != nil {
		InitTestTracing(tracing)
	}
	if sciond != nil {
		InitTestSciond(sciond)
	}
}

func InitTestGeneral(cfg *env.General) {
	cfg.ReconnectToDispatcher = true
}

func InitTestLogging(cfg *env.Logging) {}

func InitTestMetrics(cfg *env.Metrics) {}

func InitTestTracing(cfg *env.Tracing) {
	cfg.Enabled = true
	cfg.Debug = true
}

func InitTestSciond(cfg *env.SciondClient) {}

func CheckTest(general *env.General, logging *env.Logging,
	metrics *env.Metrics, tracing *env.Tracing, sciond *env.SciondClient, id string) {
	if general != nil {
		CheckTestGeneral(general, id)
	}
	if logging != nil {
		CheckTestLogging(logging, id)
	}
	if metrics != nil {
		CheckTestMetrics(metrics)
	}
	if tracing != nil {
		CheckTestTracing(tracing)
	}
	if sciond != nil {
		CheckTestSciond(sciond, id)
	}
}

func CheckTestGeneral(cfg *env.General, id string) {
	SoMsg("ID correct", cfg.ID, ShouldEqual, id)
	SoMsg("ConfigDir correct", cfg.ConfigDir, ShouldEqual, "/etc/scion")
	SoMsg("Topology correct", cfg.Topology, ShouldEqual,
		filepath.Join(cfg.ConfigDir, env.DefaultTopologyPath))
	SoMsg("ReconnectToDispatcher correct", cfg.ReconnectToDispatcher, ShouldBeFalse)
}

func CheckTestLogging(cfg *env.Logging, id string) {
	SoMsg("Path correct", cfg.File.Path, ShouldEqual, fmt.Sprintf("/var/log/scion/%s.log", id))
	SoMsg("FileLevel correct", cfg.File.Level, ShouldEqual, log.DefaultFileLevel)
	SoMsg("Size correct", cfg.File.Size, ShouldEqual, log.DefaultFileSizeMiB)
	SoMsg("MaxAge correct", cfg.File.MaxAge, ShouldEqual, log.DefaultFileMaxAgeDays)
	SoMsg("MaxBackups correct", cfg.File.MaxBackups, ShouldEqual, log.DefaultFileMaxBackups)
	SoMsg("Flush correct", *cfg.File.FlushInterval, ShouldEqual, log.DefaultFileFlushSeconds)

	SoMsg("ConsoleLevel correct", cfg.Console.Level, ShouldEqual, log.DefaultConsoleLevel)
}

func CheckTestMetrics(cfg *env.Metrics) {
	SoMsg("Prometheus correct", cfg.Prometheus, ShouldEqual, "")
}

func CheckTestTracing(cfg *env.Tracing) {
	SoMsg("Enabled correct", cfg.Enabled, ShouldBeFalse)
	SoMsg("Debug correct", cfg.Debug, ShouldBeFalse)
	SoMsg("Agent correct", cfg.Agent, ShouldEqual,
		fmt.Sprintf("%s:%d", jaeger.DefaultUDPSpanServerHost, jaeger.DefaultUDPSpanServerPort))
}

func CheckTestSciond(cfg *env.SciondClient, id string) {
	SoMsg("Path correct", cfg.Path, ShouldEqual, sciond.DefaultSCIONDPath)
	SoMsg("InitialConnectPeriod correct", cfg.InitialConnectPeriod.Duration, ShouldEqual,
		env.SciondInitConnectPeriod)
}
