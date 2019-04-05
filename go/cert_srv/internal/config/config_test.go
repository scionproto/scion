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

package config

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery/idiscoverytest"
	"github.com/scionproto/scion/go/lib/truststorage/truststoragetest"
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

func TestConfig_InitDefaults(t *testing.T) {
	Convey("Load Conf", t, func() {
		var cfg Config
		_, err := toml.DecodeFile("testdata/cs.toml", &cfg)
		SoMsg("err", err, ShouldBeNil)

		Convey("InitDefaults does not override values", func() {
			cfg.InitDefaults()
			SoMsg("leafTime", cfg.CS.LeafReissueLeadTime.Duration, ShouldEqual, 7*time.Hour)
			SoMsg("issuerTime", cfg.CS.IssuerReissueLeadTime.Duration, ShouldEqual, 48*time.Hour)
			SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldEqual, 12*time.Second)
			SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldEqual, 6*time.Second)
			SoMsg("autoRenewal", cfg.CS.AutomaticRenewal, ShouldBeTrue)
		})
	})

	Convey("Load Default", t, func() {
		var cfg Config
		_, err := toml.DecodeReader(strings.NewReader("[cs]"), &cfg)
		SoMsg("err", err, ShouldBeNil)

		Convey("InitDefaults loads default values", func() {
			cfg.InitDefaults()
			SoMsg("leafTime", cfg.CS.LeafReissueLeadTime.Duration, ShouldEqual, LeafReissTime)
			SoMsg("issuerTime", cfg.CS.IssuerReissueLeadTime.Duration, ShouldEqual, IssuerReissTime)
			SoMsg("reissRate", cfg.CS.ReissueRate.Duration, ShouldEqual, ReissReqRate)
			SoMsg("reissTimeout", cfg.CS.ReissueTimeout.Duration, ShouldEqual, ReissueReqTimeout)
			SoMsg("autoRenewal", cfg.CS.AutomaticRenewal, ShouldBeFalse)
		})
	})
}

func InitTestConfig(cfg *Config) {
	envtest.InitTest(&cfg.General, &cfg.Logging, &cfg.Metrics, &cfg.Sciond)
	truststoragetest.InitTestConfig(&cfg.TrustDB)
	idiscoverytest.InitTestConfig(&cfg.Discovery)
	InitTestCSConfig(&cfg.CS)
}

func InitTestCSConfig(cfg *CSConfig) {
	cfg.AutomaticRenewal = true
}

func CheckTestConfig(cfg *Config, id string) {
	envtest.CheckTest(&cfg.General, &cfg.Logging, &cfg.Metrics, &cfg.Sciond, id)
	truststoragetest.CheckTestConfig(&cfg.TrustDB, id)
	idiscoverytest.CheckTestConfig(&cfg.Discovery)
	CheckTestCSConfig(&cfg.CS)
}

func CheckTestCSConfig(cfg *CSConfig) {
	SoMsg("ReissueRate correct", cfg.ReissueRate.Duration, ShouldEqual, ReissReqRate)
	SoMsg("ReissueTimeout correct", cfg.ReissueTimeout.Duration, ShouldEqual, ReissueReqTimeout)
	SoMsg("AutomaticRenewal correct", cfg.AutomaticRenewal, ShouldBeFalse)
	SoMsg("LeafReissueLeadTime correct", cfg.LeafReissueLeadTime.Duration, ShouldEqual,
		LeafReissTime)
	SoMsg("IssuerReissLeadTime correct", cfg.IssuerReissueLeadTime.Duration, ShouldEqual,
		IssuerReissTime)
}
