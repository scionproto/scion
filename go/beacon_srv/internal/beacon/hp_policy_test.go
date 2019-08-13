// Copyright 2019 ETH Zurich
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

package beacon_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/lib/hiddenpath"
)

func TestHPRegistrationFromYaml(t *testing.T) {
	var id69b5 hiddenpath.GroupId
	var idabcd hiddenpath.GroupId
	id69b5.UnmarshalText([]byte("ff00:0:110-69b5"))
	idabcd.UnmarshalText([]byte("ffaa:0:222-abcd"))

	checkRegPolicy := func(r *beacon.HPRegistration) {
		g, ok := r.HPGroups[id69b5]
		SoMsg("HPGroups has hidden group ff00:0:110-69b5", ok, ShouldBeTrue)
		SoMsg("Group ff00:0:110-69b5 is loaded", g.Group, ShouldNotEqual, hiddenpath.Group{})
		g, ok = r.HPGroups[idabcd]
		SoMsg("HPGropus has hidden group ffaa:0:222-abcd", ok, ShouldBeTrue)
		SoMsg("Group ffaa:0:222-abcd is loaded", g.Group, ShouldNotEqual, hiddenpath.Group{})

		_, ok = r.HPPolicies[2].Hidden[id69b5]
		SoMsg("Policies has hidden group ff00:0:110-69b5", ok, ShouldBeTrue)
		_, ok = r.HPPolicies[2].Hidden[idabcd]
		SoMsg("Policies has hidden group ffaa:0:222-abcd", ok, ShouldBeTrue)

		SoMsg("IFID 2 Public RegUP", r.HPPolicies[2].Public.RegUp, ShouldBeTrue)
		SoMsg("IFID 2 Public RegDown", r.HPPolicies[2].Public.RegDown, ShouldBeTrue)
		SoMsg("IFID 2 ff00:0:110-69b5 RegUp", r.HPPolicies[2].Hidden[id69b5].RegUp, ShouldBeTrue)
		SoMsg("IFID 2 ff00:0:110-69b5 RegDown", r.HPPolicies[2].Hidden[id69b5].RegDown, ShouldBeTrue)
		SoMsg("IFID 2 ffaa:0:222-abcd RegUp", r.HPPolicies[2].Hidden[idabcd].RegUp, ShouldBeTrue)
		SoMsg("IFID 2 ffaa:0:222-abcd RegDown", r.HPPolicies[2].Hidden[idabcd].RegDown, ShouldBeTrue)
		SoMsg("IFID 3 Public RegUP", r.HPPolicies[3].Public.RegUp, ShouldBeTrue)
		SoMsg("IFID 3 Public RegDown", r.HPPolicies[3].Public.RegDown, ShouldBeTrue)
		SoMsg("IFID3 no hidden policies", len(r.HPPolicies[3].Hidden), ShouldEqual, 0)
	}

	Convey("Given a policy file", t, func() {
		fn := "testdata/hp_policy.yml"
		Convey("The policy is parsed correctly", func() {
			p, err := beacon.LoadHPRegFromYaml(fn)
			SoMsg("err", err, ShouldBeNil)
			checkRegPolicy(p)
		})
	})
}
