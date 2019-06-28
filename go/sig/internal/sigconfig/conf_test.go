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
	"bytes"
	"net"
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/xtest"
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
	envtest.InitTest(nil, &cfg.Logging, &cfg.Metrics, nil, &cfg.Sciond)
	InitTestSigConf(&cfg.Sig)
}

func InitTestSigConf(cfg *SigConf) {

}

func CheckTestConfig(cfg *Config, id string) {
	envtest.CheckTest(nil, &cfg.Logging, &cfg.Metrics, nil, &cfg.Sciond, id)
	CheckTestSigConf(&cfg.Sig, id)
}

func CheckTestSigConf(cfg *SigConf, id string) {
	SoMsg("ID correct", cfg.ID, ShouldEqual, "sig4")
	SoMsg("SIGConfig correct", cfg.SIGConfig, ShouldEqual, "/etc/scion/sig/sig.json")
	SoMsg("IA correct", cfg.IA, ShouldResemble, xtest.MustParseIA("1-ff00:0:113"))
	SoMsg("IP correct", cfg.IP, ShouldResemble, net.ParseIP("192.0.2.100"))
	SoMsg("CtrlPort correct", cfg.CtrlPort, ShouldEqual, DefaultCtrlPort)
	SoMsg("EncapPort correct", cfg.EncapPort, ShouldEqual, DefaultEncapPort)
	SoMsg("Dispatcher correct", cfg.Dispatcher, ShouldEqual, "")
	SoMsg("Tun correct", cfg.Tun, ShouldEqual, DefaultTunName)
	SoMsg("TunRTableId correct", cfg.TunRTableId, ShouldEqual, DefaultTunRTableId)
}
