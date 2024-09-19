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

package staticinfo_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/segment/extensions/staticinfo"
	"github.com/scionproto/scion/pkg/segment/iface"
)

func TestRoundtripStaticInfoExtension(t *testing.T) {
	testCases := map[string]*staticinfo.Extension{
		"nil":   nil,
		"empty": {},
		"empty_non_nil": {
			Geo:      make(staticinfo.GeoInfo),
			LinkType: make(staticinfo.LinkTypeInfo),
		},
		"latency": {
			Latency: staticinfo.LatencyInfo{
				Intra: map[iface.ID]time.Duration{
					10: 10 * time.Millisecond,
					11: 11 * time.Millisecond,
				},
				Inter: map[iface.ID]time.Duration{
					11: 111 * time.Millisecond,
				},
			},
		},
		"bandwidth": {
			Bandwidth: staticinfo.BandwidthInfo{
				Intra: map[iface.ID]uint64{
					10: 1,              // 1Kbit/s
					11: 10_000_000_000, // 10Tbit/s
				},
				Inter: map[iface.ID]uint64{
					11: 2_000_000,
				},
			},
		},
		"link_type": {
			LinkType: staticinfo.LinkTypeInfo{
				1: staticinfo.LinkTypeDirect,
				2: staticinfo.LinkTypeMultihop,
				3: staticinfo.LinkTypeOpennet,
			},
		},
		"geo": {
			Geo: staticinfo.GeoInfo{
				1: staticinfo.GeoCoordinates{
					Latitude:  48.858222,
					Longitude: 2.2945,
					Address:   "Eiffel Tower\n7th arrondissement\nParis\nFrance",
				},
			},
		},
		"internal_hops": {
			InternalHops: map[iface.ID]uint32{
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
			pb := staticinfo.ToPB(extn)
			actual := staticinfo.FromPB(pb)
			// Ignore nil vs empty map; replace empty by nil before check
			nilEmptyMaps(extn)
			nilEmptyMaps(actual)
			assert.Equal(t, extn, actual)
		})
	}
}

func nilEmptyMaps(si *staticinfo.Extension) {
	if si == nil {
		return
	}
	if len(si.Latency.Intra) == 0 {
		si.Latency.Intra = nil
	}
	if len(si.Latency.Inter) == 0 {
		si.Latency.Inter = nil
	}
	if len(si.Bandwidth.Intra) == 0 {
		si.Bandwidth.Intra = nil
	}
	if len(si.Bandwidth.Inter) == 0 {
		si.Bandwidth.Inter = nil
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
