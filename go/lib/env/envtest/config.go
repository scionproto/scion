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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
)

func InitTest(general *env.General, logging *env.Logging,
	metrics *env.Metrics, sciond *env.SciondClient) {
	if general != nil {
		InitTestGeneral(general)
	}
	if logging != nil {
		InitTestLogging(logging)
	}
	if metrics != nil {
		InitTestMetrics(metrics)
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

func InitTestSciond(cfg *env.SciondClient) {}

func CheckTest(general *env.General, logging *env.Logging,
	metrics *env.Metrics, sciond *env.SciondClient, id string) {
	if general != nil {
		CheckTestGeneral(general, id)
	}
	if logging != nil {
		CheckTestLogging(logging, id)
	}
	if metrics != nil {
		CheckTestMetrics(metrics)
	}
	if sciond != nil {
		CheckTestSciond(sciond, id)
	}
}

func CheckTestGeneral(cfg *env.General, id string) {
	SoMsg("ID correct", cfg.ID, ShouldEqual, id)
	SoMsg("ConfigDir correct", cfg.ConfigDir, ShouldEqual, "/etc/scion")
	SoMsg("Topology correct", cfg.Topology, ShouldEqual, "/etc/scion/topology.json")
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

func CheckTestSciond(cfg *env.SciondClient, id string) {
	SoMsg("Path correct", cfg.Path, ShouldEqual, "/run/shm/sciond/default.sock")
	SoMsg("InitialConnectPeriod correct", cfg.InitialConnectPeriod.Duration, ShouldEqual,
		env.SciondInitConnectPeriod)
}
