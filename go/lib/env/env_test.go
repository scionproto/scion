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

package env

import (
	"io/ioutil"
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"
)

type TestConfig struct {
	General General
	Logging Logging
	Metrics Metrics
	Infra   Infra
	Trust   Trust
}

func TestLoadBase(t *testing.T) {
	Convey("Load", t, func() {
		var cfg TestConfig
		_, err := toml.DecodeFile("testdata/ps.toml", &cfg)
		SoMsg("err", err, ShouldBeNil)

		err = InitGeneral(&cfg.General)
		SoMsg("err", err, ShouldBeNil)
		err = InitLogging(&cfg.Logging)
		SoMsg("err", err, ShouldBeNil)
		err = InitInfra(&cfg.Infra, cfg.General.ID, ioutil.Discard, cfg.General.Topology)
		SoMsg("err", err, ShouldBeNil)

		SoMsg("specific topology is preferred", cfg.General.TopologyPath, ShouldEqual,
			"testdata/dir/topology.json")
		SoMsg("topology bind is preferred", cfg.Infra.Bind.String(), ShouldEqual,
			"1-ff00:0:110,[127.0.0.55]:30073")
		SoMsg("topology public is preferred", cfg.Infra.Public.String(), ShouldEqual,
			"1-ff00:0:110,[127.0.0.55]:30073")
	})
}
