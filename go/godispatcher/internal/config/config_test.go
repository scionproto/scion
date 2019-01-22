// Copyright 2018 ETH Zurich
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
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

func TestSampleCorrect(t *testing.T) {
	Convey("Load", t, func() {
		var cfg Config
		_, err := toml.Decode(Sample, &cfg)
		SoMsg("err", err, ShouldBeNil)

		SoMsg("logging.file.Path", cfg.Logging.File.Path, ShouldEqual,
			"/var/log/scion/dispatcher.log")
		SoMsg("logging.file.Level", cfg.Logging.File.Level, ShouldEqual, "debug")
		SoMsg("logging.file.FlushInterval", *cfg.Logging.File.FlushInterval, ShouldEqual, 5)
		SoMsg("logging.console.Level", cfg.Logging.Console.Level, ShouldEqual, "crit")

		SoMsg("ID", cfg.Dispatcher.ID, ShouldEqual, "disp")
		SoMsg("ApplicationSocket", cfg.Dispatcher.ApplicationSocket, ShouldEqual,
			reliable.DefaultDispPath)
		SoMsg("OverlayPort", cfg.Dispatcher.OverlayPort, ShouldEqual, overlay.EndhostPort)
		SoMsg("DeleteSocket", cfg.Dispatcher.DeleteSocket, ShouldBeFalse)
	})
}
