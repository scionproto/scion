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
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/env/envtest"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery/idiscoverytest"
	"github.com/scionproto/scion/go/lib/pathstorage/pathstoragetest"
	"github.com/scionproto/scion/go/lib/sciond"
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
	envtest.InitTest(&cfg.General, &cfg.Logging, &cfg.Metrics, &cfg.Tracing, nil)
	truststoragetest.InitTestConfig(&cfg.TrustDB)
	idiscoverytest.InitTestConfig(&cfg.Discovery)
	InitTestSDConfig(&cfg.SD)
}

func InitTestSDConfig(cfg *SDConfig) {
	cfg.DeleteSocket = true
	pathstoragetest.InitTestPathDBConf(&cfg.PathDB)
	pathstoragetest.InitTestRevCacheConf(&cfg.RevCache)
}

func CheckTestConfig(cfg *Config, id string) {
	envtest.CheckTest(&cfg.General, &cfg.Logging, &cfg.Metrics, &cfg.Tracing, nil, id)
	truststoragetest.CheckTestConfig(&cfg.TrustDB, id)
	idiscoverytest.CheckTestConfig(&cfg.Discovery)
	CheckTestSDConfig(&cfg.SD, id)
}

func CheckTestSDConfig(cfg *SDConfig, id string) {
	pathstoragetest.CheckTestPathDBConf(&cfg.PathDB, id)
	pathstoragetest.CheckTestRevCacheConf(&cfg.RevCache)
	SoMsg("Reliable correct", cfg.Reliable, ShouldEqual, sciond.DefaultSCIONDPath)
	SoMsg("Unix correct", cfg.Unix, ShouldEqual, "/run/shm/sciond/default-unix.sock")
	SoMsg("Public correct", cfg.Public.String(), ShouldEqual,
		"1-ff00:0:110,[127.0.0.1]:0 (UDP)")
	SoMsg("QueryInterval correct", cfg.QueryInterval.Duration, ShouldEqual, DefaultQueryInterval)
	SoMsg("DeleteSocket set", cfg.DeleteSocket, ShouldBeFalse)
}
