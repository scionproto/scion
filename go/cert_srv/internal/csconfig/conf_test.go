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

package csconfig

import (
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"
)

type TestConfig struct {
	CS *Conf
}

func TestLoadConf(t *testing.T) {
	Convey("Load Conf", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeFile("testdata/csconfig.toml", &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("leafTime", cfg.CS.LeafReissueTime.Duration, ShouldEqual, 7*time.Hour)
		SoMsg("issuerTime", cfg.CS.IssuerReissueTime.Duration, ShouldEqual, 2*24*time.Hour)
		SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldEqual, 12*time.Second)
		SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldEqual, 6*time.Second)
	})

	Convey("Load Default", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeReader(strings.NewReader("[cs]"), &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("leafTime", cfg.CS.LeafReissueTime.Duration, ShouldBeZeroValue)
		SoMsg("issuerTime", cfg.CS.IssuerReissueTime.Duration, ShouldBeZeroValue)
		SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldBeZeroValue)
		SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldBeZeroValue)
	})
}

func TestConfig_Init(t *testing.T) {
	Convey("Load Conf", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeFile("testdata/csconfig.toml", &cfg)
		SoMsg("err", err, ShouldBeNil)

		Convey("Init does not override values", func() {
			err := cfg.CS.Init("testdata")
			SoMsg("err", err, ShouldBeNil)
			SoMsg("leafTime", cfg.CS.LeafReissueTime.Duration, ShouldEqual, 7*time.Hour)
			SoMsg("issuerTime", cfg.CS.IssuerReissueTime.Duration, ShouldEqual, 48*time.Hour)
			SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldEqual, 12*time.Second)
			SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldEqual, 6*time.Second)
		})
	})

	Convey("Load Default", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeReader(strings.NewReader("[cs]"), &cfg)
		SoMsg("err", err, ShouldBeNil)

		Convey("Init loads default values", func() {
			err := cfg.CS.Init("testdata")
			SoMsg("err", err, ShouldBeNil)
			SoMsg("leafTime", cfg.CS.LeafReissueTime.Duration, ShouldEqual, 6*time.Hour)
			SoMsg("issuerTime", cfg.CS.IssuerReissueTime.Duration, ShouldEqual, IssuerReissTime)
			SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldEqual, ReissReqRate)
			SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldEqual, ReissueReqTimeout)
		})
	})
}
