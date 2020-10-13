// Copyright 2020 ETH Zurich
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

package seg

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/common"
)

func TestRoundtripStaticInfoExtension(t *testing.T) {
	testCases := map[string]*StaticInfoExtension{
		"nil":   nil,
		"empty": {},
		"empty_non_nil": {
			Geo:      make(GeoInfo),
			LinkType: make(LinkTypeInfo),
		},
		"latency": {
			Latency: &LatencyInfo{
				Intra: map[common.IFIDType]time.Duration{
					10: 10 * time.Millisecond,
					11: 11 * time.Millisecond,
				},
				Inter: map[common.IFIDType]time.Duration{
					11: 111 * time.Millisecond,
				},
			},
		},
		"bandwidth": {
			Bandwidth: &BandwidthInfo{
				Intra: map[common.IFIDType]uint32{
					10: 10_000_000,
					11: 11_000_000,
				},
				Inter: map[common.IFIDType]uint32{
					11: 2_000_000,
				},
			},
		},
		"link_type": {
			LinkType: LinkTypeInfo{
				1: LinkTypeDirect,
				2: LinkTypeMultihop,
				3: LinkTypeOpennet,
			},
		},
		"geo": {
			Geo: GeoInfo{
				1: GeoCoordinates{
					Latitude:  48.858222,
					Longitude: 2.2945,
					Address:   "Eiffel Tower\n7th arrondissement\nParis\nFrance",
				},
			},
		},
		"internal_hops": {
			InternalHops: map[common.IFIDType]uint32{
				10: 2,
				11: 3,
			},
		},
		"note": {
			Note: "test",
		},
	}

	for name, extn := range testCases {
		t.Run(name, func(t *testing.T) {
			pb := staticInfoExtensionToPB(extn)
			actual, err := staticInfoExtensionFromPB(pb)
			require.NoError(t, err)
			// Ignore nil vs empty map; replace empty by nil before check
			nilEmptyMaps(extn)
			nilEmptyMaps(actual)
			assert.Equal(t, extn, actual)
		})
	}
}

func nilEmptyMaps(si *StaticInfoExtension) {
	if si == nil {
		return
	}
	if si.Latency != nil {
		if len(si.Latency.Intra) == 0 {
			si.Latency.Intra = nil
		}
		if len(si.Latency.Inter) == 0 {
			si.Latency.Inter = nil
		}
	}
	if si.Bandwidth != nil {
		if len(si.Bandwidth.Intra) == 0 {
			si.Bandwidth.Intra = nil
		}
		if len(si.Bandwidth.Inter) == 0 {
			si.Bandwidth.Inter = nil
		}
	}
	if len(si.Geo) == 0 {
		si.Geo = nil
	}
	if len(si.LinkType) == 0 {
		si.LinkType = nil
	}
	if len(si.InternalHops) == 0 {
		si.InternalHops = nil
	}
}
