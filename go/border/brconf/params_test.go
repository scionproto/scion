// Copyright 2019 Anapaya Systems
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

package brconf

import (
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery/idiscoverytest"
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
	envtest.InitTest(&cfg.General, &cfg.Logging, &cfg.Metrics, nil, nil)
	InitTestDiscoveryConfig(&cfg.Discovery)
	InitTestBRConfig(&cfg.BR)
}
func InitTestDiscoveryConfig(cfg *Discovery) {
	cfg.AllowSemiMutable = true
	idiscoverytest.InitTestConfig(&cfg.Config)
}

func InitTestBRConfig(cfg *BR) {
	cfg.Profile = true
}

func CheckTestConfig(cfg *Config, id string) {
	envtest.CheckTest(&cfg.General, &cfg.Logging, &cfg.Metrics, nil, nil, id)
	CheckTestDiscoveryConfig(&cfg.Discovery)
	CheckTestBRConfig(&cfg.BR)
}

func CheckTestDiscoveryConfig(cfg *Discovery) {
	SoMsg("AllowSemiMutable correct", cfg.AllowSemiMutable, ShouldBeFalse)
	idiscoverytest.CheckTestConfig(&cfg.Config)
}

func CheckTestBRConfig(cfg *BR) {
	SoMsg("Profile correct", cfg.Profile, ShouldBeFalse)
	SoMsg("RollbackFailAction correct", cfg.RollbackFailAction, ShouldEqual, FailActionFatal)
}
