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
	"net"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/xtest"
)

type TestConfig struct {
	Logging env.Logging
	Metrics env.Metrics
	Sciond  env.SciondClient `toml:"sd_client"`
	Sig     Conf
}

func TestSample(t *testing.T) {
	Convey("Sample values are correct", t, func() {
		var cfg TestConfig
		// Set to wrong string to make sure value from file is taken.
		cfg.Sig.Dispatcher = "wrong one"
		_, err := toml.Decode(Sample, &cfg)
		SoMsg("err", err, ShouldBeNil)

		// Sig values
		SoMsg("ID correct", cfg.Sig.ID, ShouldEqual, "sig4")
		SoMsg("SIGConfig correct", cfg.Sig.SIGConfig, ShouldEqual, "/etc/scion/sig/sig.json")
		SoMsg("IA correct", cfg.Sig.IA, ShouldResemble, xtest.MustParseIA("1-ff00:0:113"))
		SoMsg("IP correct", cfg.Sig.IP, ShouldResemble, net.ParseIP("192.0.2.100"))
		SoMsg("CtrlPort correct", cfg.Sig.CtrlPort, ShouldEqual, DefaultCtrlPort)
		SoMsg("EncapPort correct", cfg.Sig.EncapPort, ShouldEqual, DefaultEncapPort)
		SoMsg("Dispatcher correct", cfg.Sig.Dispatcher, ShouldEqual, "")
		SoMsg("Tun correct", cfg.Sig.Tun, ShouldEqual, "sig")
		SoMsg("TunRTableId correct", cfg.Sig.TunRTableId, ShouldEqual, DefaultTunRTableId)

		// Sciond values
		SoMsg("SCIOND Path correct", cfg.Sciond.Path, ShouldEqual, sciond.DefaultSCIONDPath)
		SoMsg("SCIOND Reconnect duration correct", cfg.Sciond.InitialConnectPeriod.Duration,
			ShouldEqual, 20*time.Second)

		// Logging values
		SoMsg("LogFile correct", cfg.Logging.File.Path, ShouldEqual, "/var/log/scion/sig4.log")
		SoMsg("LogLvl correct", cfg.Logging.File.Level, ShouldEqual, "debug")
		SoMsg("LogFlush correct", *cfg.Logging.File.FlushInterval, ShouldEqual, 5)
		SoMsg("LogConsoleLvl correct", cfg.Logging.Console.Level, ShouldEqual, "crit")

		// Metrics
		SoMsg("Prom correct", cfg.Metrics.Prometheus, ShouldEqual, "127.0.0.1:8000")
	})
}
