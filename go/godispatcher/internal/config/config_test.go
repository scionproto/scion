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
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

func TestConfigSample(t *testing.T) {
	Convey("Sample is correct", t, func() {
		var sample bytes.Buffer
		var cfg Config
		cfg.Sample(&sample, nil, nil)

		InitTestConfig(&cfg)
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)
		CheckTestConfig(&cfg, idSample)
	})
}

func InitTestConfig(cfg *Config) {
	envtest.InitTest(nil, &cfg.Logging, &cfg.Metrics, nil)
	cfg.Dispatcher.DeleteSocket = true
	cfg.Dispatcher.PerfData = "Invalid"
}

func CheckTestConfig(cfg *Config, id string) {
	envtest.CheckTest(nil, &cfg.Logging, &cfg.Metrics, nil, id)
	SoMsg("ID", cfg.Dispatcher.ID, ShouldEqual, id)
	SoMsg("ApplicationSocket", cfg.Dispatcher.ApplicationSocket, ShouldEqual,
		reliable.DefaultDispPath)
	SoMsg("OverlayPort", cfg.Dispatcher.OverlayPort, ShouldEqual, overlay.EndhostPort)
	SoMsg("PerfData", cfg.Dispatcher.PerfData, ShouldBeEmpty)
	SoMsg("DeleteSocket", cfg.Dispatcher.DeleteSocket, ShouldBeFalse)
}
