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

package config

import (
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/beaconstorage/beaconstoragetest"
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

func InitTestConfig(cfg *Config) {
	envtest.InitTest(&cfg.General, &cfg.Logging, &cfg.Metrics, nil)
	truststoragetest.InitTestConfig(&cfg.TrustDB)
	beaconstoragetest.InitTestBeaconDBConf(&cfg.BeaconDB)
	idiscoverytest.InitTestConfig(&cfg.Discovery)
	InitTestBSConfig(&cfg.BS)
}

func InitTestBSConfig(cfg *BSConfig) {
	InitTestPolicies(&cfg.Policies)
}

func InitTestPolicies(cfg *Policies) {
	cfg.Propagation = "test"
	cfg.CoreRegistration = "test"
	cfg.UpRegistration = "test"
	cfg.DownRegistration = "test"
}

func CheckTestConfig(cfg *Config, id string) {
	envtest.CheckTest(&cfg.General, &cfg.Logging, &cfg.Metrics, nil, id)
	truststoragetest.CheckTestConfig(&cfg.TrustDB, id)
	beaconstoragetest.CheckTestBeaconDBConf(&cfg.BeaconDB, id)
	idiscoverytest.CheckTestConfig(&cfg.Discovery)
	CheckTestBSConfig(&cfg.BS)
}

func CheckTestBSConfig(cfg *BSConfig) {
	SoMsg("KeepaliveTimeout", cfg.KeepaliveTimeout.Duration, ShouldEqual, DefaultKeepaliveTimeout)
	SoMsg("KeepaliveInterval", cfg.KeepaliveInterval.Duration, ShouldEqual,
		DefaultKeepaliveInterval)
	SoMsg("OriginationInterval", cfg.OriginationInterval.Duration, ShouldEqual,
		DefaultOriginationInterval)
	SoMsg("PropagationInterval", cfg.PropagationInterval.Duration, ShouldEqual,
		DefaultPropagationInterval)
	SoMsg("RegistrationInterval", cfg.RegistrationInterval.Duration, ShouldEqual,
		DefaultRegistrationInterval)
	SoMsg("ExpiredCheckInterval", cfg.ExpiredCheckInterval.Duration, ShouldEqual,
		DefaultExpiredCheckInterval)
	CheckTestPolicies(&cfg.Policies)
}

func CheckTestPolicies(cfg *Policies) {
	SoMsg("Propagation", cfg.Propagation, ShouldEqual, "")
	SoMsg("CoreRegistration", cfg.CoreRegistration, ShouldEqual, "")
	SoMsg("UpRegistration", cfg.UpRegistration, ShouldEqual, "")
	SoMsg("DownRegistration", cfg.DownRegistration, ShouldEqual, "")
}
