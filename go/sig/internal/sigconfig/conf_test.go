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

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/xtest"
)

type TestConfig struct {
	Logging env.Logging
	Metrics env.Metrics
	Sig     Conf
}

func TestSample(t *testing.T) {
	Convey("Sample values are correct", t, func() {
		var cfg TestConfig
		_, err := toml.Decode(Sample, &cfg)
		SoMsg("err", err, ShouldBeNil)

		// Sig values
		SoMsg("ID correct", cfg.Sig.ID, ShouldEqual, "sig4")
		SoMsg("Config correct", cfg.Sig.Config, ShouldEqual, "/etc/scion/sig/sig.json")
		SoMsg("IA correct", cfg.Sig.IA, ShouldResemble, xtest.MustParseIA("1-ff00:0:113"))
		SoMsg("IP correct", cfg.Sig.IP, ShouldResemble, net.ParseIP("168.10.20.15"))
		SoMsg("CtrlPort correct", cfg.Sig.CtrlPort, ShouldEqual, uint16(10081))
		SoMsg("EncapPort correct", cfg.Sig.EncapPort, ShouldEqual, uint16(10080))
		SoMsg("SCIOND correct", cfg.Sig.Sciond, ShouldEqual, "")
		SoMsg("Dispatcher correct", cfg.Sig.Dispatcher, ShouldEqual, "")
		SoMsg("Tun correct", cfg.Sig.Tun, ShouldEqual, "sig")

		// Logging values
		SoMsg("LogFile correct", cfg.Logging.File.Path, ShouldEqual, "/var/log/scion/sig4.log")
		SoMsg("LogLvl correct", cfg.Logging.File.Level, ShouldEqual, "debug")
		SoMsg("LogFlush correct", *cfg.Logging.File.FlushInterval, ShouldEqual, 5)
		SoMsg("LogConsoleLvl correct", cfg.Logging.Console.Level, ShouldEqual, "crit")
	})
}

func TestInvalidValues(t *testing.T) {
	Convey("Test invalid ports lead to an error", t, func() {
		var cfg TestConfig
		_, err := toml.Decode(`[sig]
		CtrlPort = -1`, &cfg)
		SoMsg("Negative Port not allowed", err, ShouldNotBeNil)
		_, err = toml.Decode(`[sig]
		CtrlPort = 65536`, &cfg)
		SoMsg("Not larger than uint16", err, ShouldNotBeNil)
	})
}
