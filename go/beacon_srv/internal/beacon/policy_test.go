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

package beacon

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	ia110 = xtest.MustParseIA("1-ff00:0:110")
	ia111 = xtest.MustParseIA("1-ff00:0:111")
	ia112 = xtest.MustParseIA("1-ff00:0:112")
	ia113 = xtest.MustParseIA("1-ff00:0:113")
	ia210 = xtest.MustParseIA("2-ff00:0:210")
)

func TestLoadFromYaml(t *testing.T) {
	checkPolicy := func(p *Policy, t PolicyType) {
		SoMsg("BestSetSize", p.BestSetSize, ShouldEqual, 6)
		SoMsg("CandidateSetSize", p.CandidateSetSize, ShouldEqual, 20)
		SoMsg("Type", p.Type, ShouldEqual, t)
		SoMsg("MaxHopsLength", p.Filter.MaxHopsLength, ShouldEqual, 8)
		SoMsg("AsBlackList", p.Filter.AsBlackList, ShouldResemble, []addr.AS{ia110.A, ia111.A})
		SoMsg("IsdBlackList", p.Filter.IsdBlackList, ShouldResemble, []addr.ISD{1, 2, 3})

	}
	Convey("Given a policy file with policy type set", t, func() {
		fn := "testdata/typedPolicy.yml"
		Convey("The policy is parsed correctly if the type matches", func() {
			p, err := LoadFromYaml(fn, PropPolicy)
			SoMsg("err", err, ShouldBeNil)
			checkPolicy(p, PropPolicy)
		})
		Convey("An error is returned if the type does not match", func() {
			_, err := LoadFromYaml(fn, UpRegPolicy)
			SoMsg("err", err, ShouldNotBeNil)
		})

	})
	Convey("Given a policy file with policy type unset", t, func() {
		loadWithType := func(polType PolicyType) {
			Convey(string("Load with type "+polType+" should succeed"), func() {
				p, err := LoadFromYaml("testdata/policy.yml", polType)
				SoMsg("err", err, ShouldBeNil)
				checkPolicy(p, polType)
			})
		}
		for _, t := range []PolicyType{PropPolicy, UpRegPolicy, DownRegPolicy, CoreRegPolicy} {
			loadWithType(t)
		}
	})
}

func TestFilterApply(t *testing.T) {
	Convey("Given a filter", t, func() {
		f := Filter{
			MaxHopsLength: 2,
			AsBlackList:   []addr.AS{ia112.A},
			IsdBlackList:  []addr.ISD{2},
		}
		testCases := []struct {
			Name         string
			Beacon       Beacon
			ShouldFilter bool
		}{
			{
				Name:         "Accepted: [1-ff00:0:110, 1-ff00:0:111]",
				Beacon:       newTestBeacon(ia110, ia111),
				ShouldFilter: false,
			},
			{
				Name:         "Too Long: [1-ff00:0:110, 1-ff00:0:111, 1-ff00:0:113]",
				Beacon:       newTestBeacon(ia110, ia111, ia113),
				ShouldFilter: true,
			},
			{
				Name:         "Blacklisted AS: [1-ff00:0:112]",
				Beacon:       newTestBeacon(ia112),
				ShouldFilter: true,
			},
			{
				Name:         "Blacklisted ISD[2-ff00:0:210]",
				Beacon:       newTestBeacon(ia210),
				ShouldFilter: true,
			},
		}

		for _, test := range testCases {
			Convey(test.Name, func() {
				if test.ShouldFilter {
					SoMsg("filter", f.Apply(test.Beacon), ShouldNotBeNil)
				} else {
					SoMsg("filter", f.Apply(test.Beacon), ShouldBeNil)
				}
			})
		}
	})

}

func newTestBeacon(hops ...addr.IA) Beacon {
	var entries []*seg.ASEntry
	for _, hop := range hops {
		entries = append(entries, &seg.ASEntry{RawIA: hop.IAInt()})
	}
	b := Beacon{
		Segment: &seg.PathSegment{
			ASEntries: entries,
		},
	}
	return b
}
