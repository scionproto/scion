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
	return nil
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

func TestDispatchGroups(t *testing.T) {

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
