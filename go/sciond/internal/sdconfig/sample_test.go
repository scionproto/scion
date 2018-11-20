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

package sdconfig

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
	SD      Config
}

func TestSampleCorrect(t *testing.T) {
	Convey("Load", t, func() {
		var cfg TestConfig
		// Make sure DeleteSocket is set.
		cfg.SD.DeleteSocket = true
		_, err := toml.Decode(Sample, &cfg)
		SoMsg("err", err, ShouldBeNil)

		// Non-sdconfig specific
		SoMsg("ID correct", cfg.General.ID, ShouldEqual, "sd")
		SoMsg("ConfigDir correct", cfg.General.ConfigDir, ShouldEqual, "/etc/scion")
		SoMsg("LogFile correct", cfg.Logging.File.Path, ShouldEqual, "/var/log/scion/sd.log")
		SoMsg("LogLvl correct", cfg.Logging.File.Level, ShouldEqual, "debug")
		SoMsg("LogFlush correct", *cfg.Logging.File.FlushInterval, ShouldEqual, 5)
		SoMsg("LogConsoleLvl correct", cfg.Logging.Console.Level, ShouldEqual, "crit")
		SoMsg("TrustDB.Backend correct", cfg.TrustDB.Backend, ShouldEqual, "sqlite")
		SoMsg("TrustDB.Connection correct", cfg.TrustDB.Connection,
			ShouldEqual, "/var/lib/scion/spki/sd.trust.db")

		// sdconfig specific
		SoMsg("PathDB.Backend correct", cfg.SD.PathDB.Backend, ShouldEqual, "sqlite")
		SoMsg("PathDB.Connection correct", cfg.SD.PathDB.Connection, ShouldEqual,
			"/var/lib/scion/sd.path.db")
		SoMsg("RevCache.Backend correct", cfg.SD.RevCache.Backend, ShouldEqual, "mem")
		SoMsg("RevCache.Connection correct", cfg.SD.RevCache.Connection, ShouldEqual, "")
		SoMsg("Reliable correct", cfg.SD.Reliable, ShouldEqual, "/run/shm/sciond/default.sock")
		SoMsg("Unix correct", cfg.SD.Unix, ShouldEqual, "/run/shm/sciond/default-unix.sock")
		SoMsg("Public correct", cfg.SD.Public.String(), ShouldEqual,
			"1-ff00:0:110,[127.0.0.1]:0 (UDP)")
		SoMsg("QueryInterval correct", cfg.SD.QueryInterval.Duration, ShouldEqual, 5*time.Minute)
		SoMsg("DeleteSocket set", cfg.SD.DeleteSocket, ShouldBeFalse)
	})
}
