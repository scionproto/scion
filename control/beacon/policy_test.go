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

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	seg "github.com/scionproto/scion/pkg/segment"
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
	tests := map[string]struct {
		File         string
		Type         beacon.PolicyType
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"policy with matching type": {
			File:         "testdata/typedPolicy.yml",
			Type:         beacon.PropPolicy,
			ErrAssertion: assert.NoError,
		},
		"policy with wrong type": {
			File:         "testdata/typedPolicy.yml",
			Type:         beacon.UpRegPolicy,
			ErrAssertion: assert.Error,
		},
		"policy without type": {
			File:         "testdata/policy.yml",
			Type:         beacon.PropPolicy,
			ErrAssertion: assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := beacon.LoadPolicyFromYaml(test.File, test.Type)
			test.ErrAssertion(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, 6, p.BestSetSize)
			assert.Equal(t, 20, p.CandidateSetSize)
			assert.Equal(t, test.Type, p.Type)
			assert.Equal(t, uint8(42), *p.MaxExpTime)
			assert.Equal(t, 8, p.Filter.MaxHopsLength)
			assert.Equal(t, []addr.AS{ia110.AS(), ia111.AS()}, p.Filter.AsBlackList)
			assert.Equal(t, []addr.ISD{1, 2, 3}, p.Filter.IsdBlackList)
			assert.True(t, *p.Filter.AllowIsdLoop)
		})
	}
}

func TestFilterApply(t *testing.T) {
	defaultFilter := &beacon.Filter{
		MaxHopsLength: 2,
		AsBlackList:   []addr.AS{ia112.AS()},
		IsdBlackList:  []addr.ISD{2},
		AllowIsdLoop:  &false_val,
	}
	testCases := []struct {
		Name         string
		Beacon       beacon.Beacon
		Filter       *beacon.Filter
		ErrAssertion assert.ErrorAssertionFunc
	}{
		{
			Name:         "Accepted: [1-ff00:0:110, 1-ff00:0:111]",
			Beacon:       newTestBeacon(ia110, ia111),
			Filter:       defaultFilter,
			ErrAssertion: assert.NoError,
		},
		{
			Name:         "Too Long: [1-ff00:0:110, 1-ff00:0:111, 1-ff00:0:113]",
			Beacon:       newTestBeacon(ia110, ia111, ia113),
			Filter:       defaultFilter,
			ErrAssertion: assert.Error,
		},
		{
			Name:         "Blacklisted AS: [1-ff00:0:112]",
			Beacon:       newTestBeacon(ia112),
			Filter:       defaultFilter,
			ErrAssertion: assert.Error,
		},
		{
			Name:         "Blacklisted ISD[2-ff00:0:210]",
			Beacon:       newTestBeacon(ia210),
			Filter:       defaultFilter,
			ErrAssertion: assert.Error,
		},
		{
			Name:         "AS Repeated [1-ff00:0:110, 1-ff00:0:110]",
			Beacon:       newTestBeacon(ia110, ia110),
			Filter:       defaultFilter,
			ErrAssertion: assert.Error,
		},
		{
			Name:         "AS loop [1-ff00:0:110, 1-ff00:0:111, 1-ff00:0:113, 1-ff00:0:110]",
			Beacon:       newTestBeacon(ia110, ia111, ia113, ia110),
			Filter:       &beacon.Filter{MaxHopsLength: 8, AllowIsdLoop: &false_val},
			ErrAssertion: assert.Error,
		},
		{
			Name:         "ISD loop [1-ff00:0:110, 3-ff00:0:310, 3-ff00:0:311, 1-ff00:0:111]",
			Beacon:       newTestBeacon(ia110, ia310, ia311, ia111),
			Filter:       &beacon.Filter{MaxHopsLength: 8, AllowIsdLoop: &false_val},
			ErrAssertion: assert.Error,
		},
		{
			Name:         "ISD/AS Loop [1-ff00:0:110, 3-ff00:0:311, 1-ff00:0:110]",
			Beacon:       newTestBeacon(ia110, ia311, ia110),
			Filter:       &beacon.Filter{MaxHopsLength: 8, AllowIsdLoop: &true_val},
			ErrAssertion: assert.Error,
		},
		{
			Name:         "ISD Loop allowed [1-ff00:0:110, 3-ff00:0:311, 1-ff00:0:111]",
			Beacon:       newTestBeacon(ia110, ia311, ia111),
			Filter:       &beacon.Filter{MaxHopsLength: 8, AllowIsdLoop: &true_val},
			ErrAssertion: assert.NoError,
		},
	}
	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			test.ErrAssertion(t, test.Filter.Apply(test.Beacon))
		})
	}
}

func TestFilterLoop(t *testing.T) {
	testCases := []struct {
		Name         string
		Beacon       beacon.Beacon
		Next         addr.IA
		AllowIsdLoop bool
		ErrAssertion assert.ErrorAssertionFunc
	}{
		{
			Name:         "AS Repeated [1-ff00:0:110, 1-ff00:0:110]",
			Beacon:       newTestBeacon(ia110),
			Next:         ia110,
			ErrAssertion: assert.Error,
		},
		{
			Name:         "AS loop [1-ff00:0:110, 1-ff00:0:111, 1-ff00:0:113, 1-ff00:0:110]",
			Beacon:       newTestBeacon(ia110, ia111, ia113, ia110),
			ErrAssertion: assert.Error,
		},
		{
			Name:         "ISD loop [1-ff00:0:110, 3-ff00:0:310, 3-ff00:0:311, 1-ff00:0:111]",
			Beacon:       newTestBeacon(ia110, ia310, ia311, ia111),
			ErrAssertion: assert.Error,
		},
		{
			Name:         "ISD/AS Loop [1-ff00:0:110, 3-ff00:0:311, 1-ff00:0:110]",
			Beacon:       newTestBeacon(ia110, ia311, ia110),
			AllowIsdLoop: true,
			ErrAssertion: assert.Error,
		},
		{
			Name:         "ISD Loop allowed [1-ff00:0:110, 3-ff00:0:311, 1-ff00:0:111]",
			Beacon:       newTestBeacon(ia110, ia311, ia111),
			AllowIsdLoop: true,
			ErrAssertion: assert.NoError,
		},
	}
	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			test.ErrAssertion(t, beacon.FilterLoop(test.Beacon, test.Next, test.AllowIsdLoop))
		})
	}
}

func newTestBeacon(hops ...addr.IA) beacon.Beacon {
	var entries []seg.ASEntry
	for _, hop := range hops {
		entries = append(entries, seg.ASEntry{Local: hop})
	}
	b := beacon.Beacon{
		Segment: &seg.PathSegment{
			ASEntries: entries,
		},
	}
	return b
}
