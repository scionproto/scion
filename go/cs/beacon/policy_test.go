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

package beacon_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/cs/beacon"
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
	ia310 = xtest.MustParseIA("3-ff00:0:310")
	ia311 = xtest.MustParseIA("3-ff00:0:311")

	false_val = false
	true_val  = true
)

func TestLoadPolicyFromYaml(t *testing.T) {
	checkPolicy := func(p *beacon.Policy, t beacon.PolicyType) {
		SoMsg("BestSetSize", p.BestSetSize, ShouldEqual, 6)
		SoMsg("CandidateSetSize", p.CandidateSetSize, ShouldEqual, 20)
		SoMsg("Type", p.Type, ShouldEqual, t)
		SoMsg("MaxExpTime", *p.MaxExpTime, ShouldEqual, 42)
		SoMsg("MaxHopsLength", p.Filter.MaxHopsLength, ShouldEqual, 8)
		SoMsg("AsBlackList", p.Filter.AsBlackList, ShouldResemble, []addr.AS{ia110.A, ia111.A})
		SoMsg("IsdBlackList", p.Filter.IsdBlackList, ShouldResemble, []addr.ISD{1, 2, 3})
		SoMsg("AllowIsdLoop", *p.Filter.AllowIsdLoop, ShouldBeTrue)

	}
	Convey("Given a policy file with policy type set", t, func() {
		fn := "testdata/typedPolicy.yml"
		Convey("The policy is parsed correctly if the type matches", func() {
			p, err := beacon.LoadPolicyFromYaml(fn, beacon.PropPolicy)
			SoMsg("err", err, ShouldBeNil)
			checkPolicy(p, beacon.PropPolicy)
		})
		Convey("An error is returned if the type does not match", func() {
			_, err := beacon.LoadPolicyFromYaml(fn, beacon.UpRegPolicy)
			SoMsg("err", err, ShouldNotBeNil)
		})

	})
	Convey("Given a policy file with policy type unset", t, func() {
		loadWithType := func(polType beacon.PolicyType) {
			Convey(string("Load with type "+polType+" should succeed"), func() {
				p, err := beacon.LoadPolicyFromYaml("testdata/policy.yml", polType)
				SoMsg("err", err, ShouldBeNil)
				checkPolicy(p, polType)
			})
		}
		for _, t := range []beacon.PolicyType{beacon.PropPolicy, beacon.UpRegPolicy,
			beacon.DownRegPolicy, beacon.CoreRegPolicy} {
			loadWithType(t)
		}
	})
}

func TestFilterApply(t *testing.T) {
	Convey("Given a filter", t, func() {
		f := beacon.Filter{
			MaxHopsLength: 2,
			AsBlackList:   []addr.AS{ia112.A},
			IsdBlackList:  []addr.ISD{2},
			AllowIsdLoop:  &false_val,
		}
		testCases := []struct {
			Name         string
			Beacon       beacon.Beacon
			Filter       *beacon.Filter
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
			{
				Name:         "AS Repeated [1-ff00:0:110, 1-ff00:0:110]",
				Beacon:       newTestBeacon(ia110, ia110),
				ShouldFilter: true,
			},
			{
				Name:         "AS loop [1-ff00:0:110, 1-ff00:0:111, 1-ff00:0:113, 1-ff00:0:110]",
				Beacon:       newTestBeacon(ia110, ia111, ia113, ia110),
				Filter:       &beacon.Filter{MaxHopsLength: 8, AllowIsdLoop: &false_val},
				ShouldFilter: true,
			},
			{
				Name:         "ISD loop [1-ff00:0:110, 3-ff00:0:310, 3-ff00:0:311, 1-ff00:0:111]",
				Beacon:       newTestBeacon(ia110, ia310, ia311, ia111),
				Filter:       &beacon.Filter{MaxHopsLength: 8, AllowIsdLoop: &false_val},
				ShouldFilter: true,
			},
			{
				Name:         "ISD/AS Loop [1-ff00:0:110, 3-ff00:0:311, 1-ff00:0:110]",
				Beacon:       newTestBeacon(ia110, ia311, ia110),
				Filter:       &beacon.Filter{MaxHopsLength: 8, AllowIsdLoop: &true_val},
				ShouldFilter: true,
			},
			{
				Name:         "ISD Loop allowed [1-ff00:0:110, 3-ff00:0:311, 1-ff00:0:111]",
				Beacon:       newTestBeacon(ia110, ia311, ia111),
				Filter:       &beacon.Filter{MaxHopsLength: 8, AllowIsdLoop: &true_val},
				ShouldFilter: false,
			},
		}

		for _, test := range testCases {
			Convey(test.Name, func() {
				testFilter := f
				if test.Filter != nil {
					testFilter = *test.Filter
				}
				xtest.SoMsgError("filter", testFilter.Apply(test.Beacon), test.ShouldFilter)
			})
		}
	})
}

func TestFilterLoop(t *testing.T) {
	testCases := []struct {
		Name         string
		Beacon       beacon.Beacon
		Next         addr.IA
		AllowIsdLoop bool
		ShouldFilter bool
	}{
		{
			Name:         "AS Repeated [1-ff00:0:110, 1-ff00:0:110]",
			Beacon:       newTestBeacon(ia110),
			Next:         ia110,
			ShouldFilter: true,
		},
		{
			Name:         "AS loop [1-ff00:0:110, 1-ff00:0:111, 1-ff00:0:113, 1-ff00:0:110]",
			Beacon:       newTestBeacon(ia110, ia111, ia113, ia110),
			ShouldFilter: true,
		},
		{
			Name:         "ISD loop [1-ff00:0:110, 3-ff00:0:310, 3-ff00:0:311, 1-ff00:0:111]",
			Beacon:       newTestBeacon(ia110, ia310, ia311, ia111),
			ShouldFilter: true,
		},
		{
			Name:         "ISD/AS Loop [1-ff00:0:110, 3-ff00:0:311, 1-ff00:0:110]",
			Beacon:       newTestBeacon(ia110, ia311, ia110),
			AllowIsdLoop: true,
			ShouldFilter: true,
		},
		{
			Name:         "ISD Loop allowed [1-ff00:0:110, 3-ff00:0:311, 1-ff00:0:111]",
			Beacon:       newTestBeacon(ia110, ia311, ia111),
			AllowIsdLoop: true,
			ShouldFilter: false,
		},
	}
	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			if test.ShouldFilter {
				if beacon.FilterLoop(test.Beacon, test.Next, test.AllowIsdLoop) == nil {
					t.Errorf("Should filter")
				}
			} else {
				xtest.FailOnErr(t, beacon.FilterLoop(test.Beacon, test.Next, test.AllowIsdLoop))
			}
		})
	}
}

func newTestBeacon(hops ...addr.IA) beacon.Beacon {
	var entries []*seg.ASEntry
	for _, hop := range hops {
		entries = append(entries, &seg.ASEntry{RawIA: hop.IAInt()})
	}
	b := beacon.Beacon{
		Segment: &seg.PathSegment{
			ASEntries: entries,
		},
	}
	return b
}
