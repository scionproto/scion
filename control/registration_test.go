// Copyright 2025 Anapaya Systems
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

package control_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beacon/mock_beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/registration"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/path/pathpol"
)

type testRegistrar struct {
	Results []beacon.Beacon
}

var _ registration.SegmentRegistrar = (*testRegistrar)(nil)

func (r *testRegistrar) RegisterSegments(
	ctx context.Context,
	beacons []beacon.Beacon,
	peers []uint16,
) *registration.RegistrationSummary {
	r.Results = beacons
	sum := registration.NewSummary()
	for _, b := range beacons {
		sum.RecordBeacon(&b)
	}
	return sum
}

func MustParseSequence(t *testing.T, seq string) *pathpol.Sequence {
	sequence, err := pathpol.NewSequence(seq)
	require.NoError(t, err)
	return sequence
}

func TestRetrieveGroupedBeacons(t *testing.T) {
	mctrl := gomock.NewController(t)
	g := graph.NewDefaultGraph(mctrl)

	stub := graph.If_111_A_112_X
	beacons := []beacon.Beacon{
		testBeacon(g, graph.If_120_X_111_B, stub),
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_X_111_B, stub),
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_X_111_B, stub),
	}

	wildCardSeq := MustParseSequence(t, "0*")
	twoHopsSeq := MustParseSequence(t, "0-0#0 0-0#0")
	threeHopsSeq := MustParseSequence(t, "0-0#0 0-0#0 0-0#0")

	type testCase struct {
		Name        string
		RegPolicies []beacon.RegistrationPolicy
		Expected    beacon.GroupedBeacons
	}

	testCases := []testCase{
		{
			Name:        "No policies",
			RegPolicies: []beacon.RegistrationPolicy{},
			Expected: beacon.GroupedBeacons{
				beacon.DEFAULT_GROUP: beacons,
			},
		},
		{
			Name: "Empty policy",
			RegPolicies: []beacon.RegistrationPolicy{
				{
					Name: "empty",
				},
			},
			Expected: beacon.GroupedBeacons{
				"empty": beacons,
			},
		},
		{
			Name: "Disjoint policies",
			RegPolicies: []beacon.RegistrationPolicy{
				{
					Name: "twoHops",
					Matcher: beacon.RegistrationPolicyMatcher{
						Sequence: twoHopsSeq,
					},
				},
				{
					Name: "threeHops",
					Matcher: beacon.RegistrationPolicyMatcher{
						Sequence: threeHopsSeq,
					},
				},
			},
			Expected: beacon.GroupedBeacons{
				"twoHops": []beacon.Beacon{
					beacons[0],
				},
				"threeHops": []beacon.Beacon{
					beacons[1],
					beacons[2],
				},
			},
		},
		{
			Name: "Overlapping policies",
			RegPolicies: []beacon.RegistrationPolicy{
				{
					Name: "all",
					Matcher: beacon.RegistrationPolicyMatcher{
						Sequence: wildCardSeq,
					},
				},
				{
					Name: "threeHops",
					Matcher: beacon.RegistrationPolicyMatcher{
						Sequence: threeHopsSeq,
					},
				},
			},
			Expected: beacon.GroupedBeacons{
				"all": []beacon.Beacon{
					beacons[0],
					beacons[1],
					beacons[2],
				},
				"threeHops": []beacon.Beacon{
					beacons[1],
					beacons[2],
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := t.Context()

			// Create a mock database that returns the beacons.
			db := mock_beacon.NewMockDB(mctrl)
			db.EXPECT().CandidateBeacons(
				gomock.Any(), gomock.Any(), gomock.Any(), addr.IA(0),
			).Return(
				beacons, nil,
			)

			policies := beacon.Policies{
				UpReg: beacon.Policy{
					RegistrationPolicies: tc.RegPolicies,
				},
			}
			store, err := beacon.NewBeaconStore(policies, db)
			require.NoError(t, err)

			beacons, err := store.SegmentsToRegister(ctx, seg.TypeUp)
			require.NoError(t, err)

			require.Equal(t, tc.Expected, beacons)
		})
	}
}

func TestGroupWriter(t *testing.T) {
	mctrl := gomock.NewController(t)
	g := graph.NewDefaultGraph(mctrl)

	stub := graph.If_111_A_112_X
	beacons := []beacon.Beacon{
		testBeacon(g, graph.If_120_X_111_B, stub),
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_X_111_B, stub),
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_X_111_B, stub),
	}

	testReg1 := &testRegistrar{}
	testReg2 := &testRegistrar{}

	type testCase struct {
		Name       string
		Input      beacon.GroupedBeacons
		Registrars map[string]*testRegistrar

		Expected map[string][]beacon.Beacon
	}

	testCases := []testCase{
		{
			Name: "Basic",
			Input: beacon.GroupedBeacons{
				"all": []beacon.Beacon{
					beacons[0],
					beacons[1],
					beacons[2],
				},
				"some": []beacon.Beacon{
					beacons[0],
					beacons[2],
				},
			},
			Registrars: map[string]*testRegistrar{
				"all":  testReg1,
				"some": testReg2,
			},
			Expected: map[string][]beacon.Beacon{
				"all": {
					beacons[0],
					beacons[1],
					beacons[2],
				},
				"some": {
					beacons[0],
					beacons[2],
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := t.Context()

			asRegistrars := make(registration.SegmentRegistrars)
			for name, reg := range tc.Registrars {
				require.Nil(t, reg.Results)
				if asRegistrars[beacon.RegPolicyTypeUp] == nil {
					asRegistrars[beacon.RegPolicyTypeUp] = make(
						map[string]registration.SegmentRegistrar,
					)
				}
				asRegistrars[beacon.RegPolicyTypeUp][name] = reg
			}

			gw := beaconing.GroupWriter{
				PolicyType: beacon.RegPolicyTypeUp,
				Registrars: asRegistrars,
			}

			_, err := gw.Write(ctx, tc.Input, nil)
			require.NoError(t, err)

			actual := make(map[string][]beacon.Beacon)
			for name, reg := range tc.Registrars {
				actual[name] = reg.Results
			}

			require.Equal(t, tc.Expected, actual)
		})
	}

}

func testBeacon(g *graph.Graph, desc ...uint16) beacon.Beacon {
	pseg := testSegment(g, desc)
	asEntry := pseg.ASEntries[pseg.MaxIdx()]
	return beacon.Beacon{
		InIfID:  asEntry.HopEntry.HopField.ConsIngress,
		Segment: pseg,
	}
}

func testSegment(g *graph.Graph, ifIDs []uint16) *seg.PathSegment {
	pseg := g.Beacon(ifIDs)
	pseg.ASEntries = pseg.ASEntries[:len(pseg.ASEntries)-1]
	return pseg
}
