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
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	. "github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
)

func InitTestConfig(t *testing.T, cfg *Config) {
	t.Helper()
	cfg.Dynamic.Enable = true
	cfg.Dynamic.Https = true
	cfg.Static.Enable = true
	cfg.Static.Https = true
	cfg.Static.Filename = "topology.json"
}

func CheckTestConfig(t *testing.T, cfg Config) {
	t.Helper()
	Convey("The static part should be correct", func() {
		checkCommon(t, cfg.Static.FetchConfig)
		SoMsg("Discovery.Static.Filename correct", cfg.Static.Filename, ShouldBeBlank)
	})
	Convey("The dynamic part should be correct", func() {
		checkCommon(t, cfg.Dynamic)
	})
}

func checkCommon(t *testing.T, cfg FetchConfig) {
	t.Helper()
	SoMsg("Enable correct", cfg.Enable, ShouldBeFalse)
	SoMsg("Timeout correct", cfg.Timeout.Duration, ShouldEqual, DefaultFetchTimeout)
	SoMsg("Https correct", cfg.Https, ShouldBeFalse)
	SoMsg("Connect.InitialPeriod correct", cfg.Connect.InitialPeriod.Duration, ShouldEqual,
		DefaultInitialConnectPeriod)
	SoMsg("Connect.FailAction correct", cfg.Connect.FailAction, ShouldEqual, FailActionContinue)

}
