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

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/truststorage"
)

type TestConfig struct {
	General env.General
	Logging env.Logging
	Metrics env.Metrics
	Infra   env.Infra
	TrustDB truststorage.TrustDBConf
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
		SoMsg("ID correct", cfg.General.ID, ShouldEqual, "ps-1")
		SoMsg("ConfigDir correct", cfg.General.ConfigDir, ShouldEqual, "/etc/scion")
		SoMsg("LogFile correct", cfg.Logging.File.Path, ShouldEqual, "/var/log/scion/ps-1.log")
		SoMsg("LogLvl correct", cfg.Logging.File.Level, ShouldEqual, "debug")
		SoMsg("LogFlush correct", *cfg.Logging.File.FlushInterval, ShouldEqual, 5)
		SoMsg("LogConsoleLvl correct", cfg.Logging.Console.Level, ShouldEqual, "crit")
		SoMsg("TrustDB.Backend correct", cfg.TrustDB.Backend, ShouldEqual, "sqlite")
		SoMsg("TrustDB.Connection correct", cfg.TrustDB.Connection, ShouldEqual,
			"/var/lib/scion/spki/ps-1.trust.db")

		// psconfig specific
		SoMsg("PathDB.Backend correct", cfg.PS.PathDB.Backend, ShouldEqual, "sqlite")
		SoMsg("PathDB.Connection correct", cfg.PS.PathDB.Connection, ShouldEqual,
			"/var/lib/scion/pathdb/ps-1.path.db")
		SoMsg("RevCache.Backend correct", cfg.PS.RevCache.Backend, ShouldEqual, "mem")
		SoMsg("RevCache.Connection correct", cfg.PS.RevCache.Connection, ShouldEqual, "")
		SoMsg("SegSync set", cfg.PS.SegSync, ShouldBeFalse)
		SoMsg("QueryInterval correct", cfg.PS.QueryInterval.Duration, ShouldEqual, 5*time.Minute)
	})
}
