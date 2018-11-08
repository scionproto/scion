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

	"github.com/scionproto/scion/go/lib/env"
)

type TestConfig struct {
	General env.General
	Logging env.Logging
	Metrics env.Metrics
	Infra   env.Infra
	Trust   env.Trust
	CS      *Conf
}

func TestSampleCorrect(t *testing.T) {
	Convey("Load", t, func() {
		var cfg TestConfig
		_, err := toml.Decode(Sample, &cfg)
		SoMsg("err", err, ShouldBeNil)

		// Non-csconfig specific
		SoMsg("ID correct", cfg.General.ID, ShouldEqual, "cs-1")
		SoMsg("ConfigDir correct", cfg.General.ConfigDir, ShouldEqual, "/etc/scion")
		SoMsg("LogFile correct", cfg.Logging.File.Path, ShouldEqual, "/var/log/scion/cs-1.log")
		SoMsg("LogLvl correct", cfg.Logging.File.Level, ShouldEqual, "debug")
		SoMsg("LogFlush correct", *cfg.Logging.File.FlushInterval, ShouldEqual, 5)
		SoMsg("LogConsoleLvl correct", cfg.Logging.Console.Level, ShouldEqual, "crit")
		SoMsg("TrustDB correct", cfg.Trust.TrustDB, ShouldEqual,
			"/var/lib/scion/spki/cs-1.trust.db")

		// csconfig specific
		SoMsg("LeafReissueLeadTime correct", cfg.CS.LeafReissueLeadTime.Duration,
			ShouldEqual, 6*time.Hour)
		SoMsg("ReissueRate correct", cfg.CS.ReissueRate.Duration, ShouldEqual, ReissReqRate)
		SoMsg("ReissueTimeout correct", cfg.CS.ReissueTimeout.Duration, ShouldEqual,
			ReissueReqTimeout)
		SoMsg("IssuerReissTime correct", cfg.CS.IssuerReissueLeadTime.Duration, ShouldEqual,
			IssuerReissTime)
		SoMsg("Reissue correct", cfg.CS.Reissue, ShouldBeFalse)
	})
}

func TestLoadConf(t *testing.T) {
	Convey("Load Conf", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeFile("testdata/csconfig.toml", &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("leafTime", cfg.CS.LeafReissueLeadTime.Duration, ShouldEqual, 7*time.Hour)
		SoMsg("issuerTime", cfg.CS.IssuerReissueLeadTime.Duration, ShouldEqual, 2*24*time.Hour)
		SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldEqual, 12*time.Second)
		SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldEqual, 6*time.Second)
		SoMsg("reissue", cfg.CS.Reissue, ShouldBeTrue)
	})

	Convey("Load Default", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeReader(strings.NewReader("[cs]"), &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("leafTime", cfg.CS.LeafReissueLeadTime.Duration, ShouldBeZeroValue)
		SoMsg("issuerTime", cfg.CS.IssuerReissueLeadTime.Duration, ShouldBeZeroValue)
		SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldBeZeroValue)
		SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldBeZeroValue)
		SoMsg("reissue", cfg.CS.Reissue, ShouldBeFalse)
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
			SoMsg("leafTime", cfg.CS.LeafReissueLeadTime.Duration, ShouldEqual, 7*time.Hour)
			SoMsg("issuerTime", cfg.CS.IssuerReissueLeadTime.Duration, ShouldEqual, 48*time.Hour)
			SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldEqual, 12*time.Second)
			SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldEqual, 6*time.Second)
			SoMsg("reissue", cfg.CS.Reissue, ShouldBeTrue)
		})
	})

	Convey("Load Default", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeReader(strings.NewReader("[cs]"), &cfg)
		SoMsg("err", err, ShouldBeNil)

		Convey("Init loads default values", func() {
			err := cfg.CS.Init("testdata")
			SoMsg("err", err, ShouldBeNil)
			SoMsg("leafTime", cfg.CS.LeafReissueLeadTime.Duration, ShouldEqual, 6*time.Hour)
			SoMsg("issuerTime", cfg.CS.IssuerReissueLeadTime.Duration, ShouldEqual, IssuerReissTime)
			SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldEqual, ReissReqRate)
			SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldEqual, ReissueReqTimeout)
			SoMsg("reissue", cfg.CS.Reissue, ShouldBeFalse)
		})
	})
}
