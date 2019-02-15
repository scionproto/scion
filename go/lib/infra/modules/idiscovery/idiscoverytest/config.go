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

package idiscoverytest

import (
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
)

func InitTestConfig(cfg *idiscovery.Config) {
	cfg.Dynamic.Enable = true
	cfg.Dynamic.Https = true
	cfg.Static.Enable = true
	cfg.Static.Https = true
	cfg.Static.Filename = "topology.json"
}

func CheckTestConfig(cfg idiscovery.Config) {
	Convey("The static part should be correct", func() {
		checkCommon(cfg.Static.FetchConfig)
		SoMsg("Discovery.Static.Filename correct", cfg.Static.Filename, ShouldBeBlank)
	})
	Convey("The dynamic part should be correct", func() {
		checkCommon(cfg.Dynamic)
	})
}

func checkCommon(cfg idiscovery.FetchConfig) {
	SoMsg("Enable correct", cfg.Enable, ShouldBeFalse)
	SoMsg("Timeout correct", cfg.Timeout.Duration, ShouldEqual, idiscovery.DefaultFetchTimeout)
	SoMsg("Https correct", cfg.Https, ShouldBeFalse)
	SoMsg("Connect.InitialPeriod correct", cfg.Connect.InitialPeriod.Duration, ShouldEqual,
		idiscovery.DefaultInitialConnectPeriod)
	SoMsg("Connect.FailAction correct", cfg.Connect.FailAction, ShouldEqual,
		idiscovery.FailActionContinue)

}
