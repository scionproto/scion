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

package psconfig

import (
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
)

type TestConfig struct {
	General env.General
	Logging env.Logging
	Metrics env.Metrics
	Infra   env.Infra
	Trust   env.Trust
	PS      Config
}

func TestSampleCorrect(t *testing.T) {
	Convey("Load", t, func() {
		var cfg TestConfig
		// Make sure SegSync is set.
		cfg.PS.SegSync = true
		_, err := toml.Decode(Sample, &cfg)
		SoMsg("err", err, ShouldBeNil)

		// Non-psconfig specific
		SoMsg("ID correct", cfg.General.ID, ShouldEqual, "ps1-ff00_0_110-1")
		SoMsg("ConfigDir correct", cfg.General.ConfigDir, ShouldEqual,
			"gen/ISD1/ASff00_0_110/ps1-ff00_0_110-1")
		SoMsg("LogFile correct", cfg.Logging.File.Path, ShouldEqual, "logs/ps1-ff00_0_110-1.log")
		SoMsg("LogFile correct", cfg.Logging.File.Path, ShouldEqual, "logs/ps1-ff00_0_110-1.log")
		SoMsg("LogLvl correct", cfg.Logging.File.Level, ShouldEqual, "debug")
		SoMsg("LogFlush correct", *cfg.Logging.File.FlushInterval, ShouldEqual, 10)
		SoMsg("LogConsoleLvl correct", cfg.Logging.Console.Level, ShouldEqual, "warn")
		SoMsg("Infra correct", cfg.Infra.Type, ShouldEqual, common.PS)
		SoMsg("TrustDB correct", cfg.Trust.TrustDB, ShouldEqual,
			"gen-cache/ps1-ff00_0_110-1.trust.db")

		// psconfig specific
		SoMsg("PathDB correct", cfg.PS.PathDB, ShouldEqual, "gen-cache/ps1-ff00_0_110-1.path.db")
		SoMsg("SegSync set", cfg.PS.SegSync, ShouldBeFalse)
		SoMsg("QueryInterval correct", cfg.PS.QueryInterval.Duration, ShouldEqual, 5*time.Minute)
	})
}
