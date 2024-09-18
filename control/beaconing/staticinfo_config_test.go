// Copyright 2020 ETH Zurich, Anapaya Systems
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

package beaconing_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/segment/extensions/staticinfo"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/private/topology"
)

const (
	latency_intra_1_2 time.Duration = 10 * time.Millisecond
	latency_intra_1_3 time.Duration = 20 * time.Millisecond
	latency_intra_1_5 time.Duration = 30 * time.Millisecond
	latency_intra_2_3 time.Duration = 70 * time.Millisecond
	latency_intra_2_5 time.Duration = 50 * time.Millisecond
	latency_intra_3_5 time.Duration = 60 * time.Millisecond
	latency_inter_1   time.Duration = 30 * time.Millisecond
	latency_inter_2   time.Duration = 40 * time.Millisecond
	latency_inter_3   time.Duration = 80 * time.Millisecond
	latency_inter_5   time.Duration = 90 * time.Millisecond

	bandwidth_intra_1_2 uint64 = 100000000
	bandwidth_intra_1_3 uint64 = 200000000
	bandwidth_intra_1_5 uint64 = 300000000
	bandwidth_intra_2_3 uint64 = 6555550
	bandwidth_intra_2_5 uint64 = 75555550
	bandwidth_intra_3_5 uint64 = 1333310
	bandwidth_inter_1   uint64 = 400000000
	bandwidth_inter_2   uint64 = 5000000
	bandwidth_inter_3   uint64 = 80
	bandwidth_inter_5   uint64 = 120

	link_type_1 staticinfo.LinkType = staticinfo.LinkTypeDirect
	link_type_2 staticinfo.LinkType = staticinfo.LinkTypeOpennet
	link_type_3 staticinfo.LinkType = staticinfo.LinkTypeMultihop
	link_type_5 staticinfo.LinkType = staticinfo.LinkTypeDirect

	hops_intra_1_2 uint32 = 2
	hops_intra_1_3 uint32 = 3
	hops_intra_1_5 uint32 = 0
	hops_intra_2_3 uint32 = 3
	hops_intra_2_5 uint32 = 1
	hops_intra_3_5 uint32 = 3
)

var (
	geo_1 = staticinfo.GeoCoordinates{
		Longitude: 62.2,
		Latitude:  47.2,
		Address:   "geo1",
	}
	geo_2 = staticinfo.GeoCoordinates{
		Longitude: 45.2,
		Latitude:  79.2,
		Address:   "geo2",
	}
	geo_3 = staticinfo.GeoCoordinates{
		Longitude: 42.23,
		Latitude:  47.22,
		Address:   "geo3",
	}
	geo_5 = staticinfo.GeoCoordinates{
		Longitude: 46.2,
		Latitude:  48.2,
		Address:   "geo5",
	}

	note = "asdf"
)

func getTestConfigData() *beaconing.StaticInfoCfg {

	w := func(d time.Duration) util.DurWrap {
		return util.DurWrap{Duration: d}
	}

	return &beaconing.StaticInfoCfg{
		Latency: map[iface.ID]beaconing.InterfaceLatencies{
			1: {
				Inter: w(latency_inter_1),
				Intra: map[iface.ID]util.DurWrap{
					2: w(latency_intra_1_2),
					3: w(latency_intra_1_3),
					5: w(latency_intra_1_5),
				},
			},
			2: {
				Inter: w(latency_inter_2),
				Intra: map[iface.ID]util.DurWrap{
					1: w(latency_intra_1_2),
					3: w(latency_intra_2_3),
					5: w(latency_intra_2_5),
				},
			},
			3: {
				Inter: w(latency_inter_3),
				Intra: map[iface.ID]util.DurWrap{
					1: w(latency_intra_1_3),
					2: w(latency_intra_2_3),
					5: w(latency_intra_3_5),
				},
			},
			5: {
				Inter: w(latency_inter_5),
				Intra: map[iface.ID]util.DurWrap{
					1: w(latency_intra_1_5),
					2: w(latency_intra_2_5),
					3: w(latency_intra_3_5),
				},
			},
		},
		Bandwidth: map[iface.ID]beaconing.InterfaceBandwidths{
			1: {
				Inter: bandwidth_inter_1,
				Intra: map[iface.ID]uint64{
					2: bandwidth_intra_1_2,
					3: bandwidth_intra_1_3,
					5: bandwidth_intra_1_5,
				},
			},
			2: {
				Inter: bandwidth_inter_2,
				Intra: map[iface.ID]uint64{
					1: bandwidth_intra_1_2,
					3: bandwidth_intra_2_3,
					5: bandwidth_intra_2_5,
				},
			},
			3: {
				Inter: bandwidth_inter_3,
				Intra: map[iface.ID]uint64{
					1: bandwidth_intra_1_3,
					2: bandwidth_intra_2_3,
					5: bandwidth_intra_3_5,
				},
			},
			5: {
				Inter: bandwidth_inter_5,
				Intra: map[iface.ID]uint64{
					1: bandwidth_intra_1_5,
					2: bandwidth_intra_2_5,
					3: bandwidth_intra_3_5,
				},
			},
		},
		LinkType: map[iface.ID]beaconing.LinkType{
			1: beaconing.LinkType(link_type_1),
			2: beaconing.LinkType(link_type_2),
			3: beaconing.LinkType(link_type_3),
			5: beaconing.LinkType(link_type_5),
		},
		Geo: map[iface.ID]beaconing.InterfaceGeodata{
			1: {geo_1.Longitude, geo_1.Latitude, geo_1.Address},
			2: {geo_2.Longitude, geo_2.Latitude, geo_2.Address},
			3: {geo_3.Longitude, geo_3.Latitude, geo_3.Address},
			5: {geo_5.Longitude, geo_5.Latitude, geo_5.Address},
		},
		Hops: map[iface.ID]beaconing.InterfaceHops{
			1: {
				Intra: map[iface.ID]uint32{
					2: hops_intra_1_2,
					3: hops_intra_1_3,
					5: hops_intra_1_5,
				},
			},
			2: {
				Intra: map[iface.ID]uint32{
					1: hops_intra_1_2,
					3: hops_intra_2_3,
					5: hops_intra_2_5,
				},
			},
			3: {
				Intra: map[iface.ID]uint32{
					1: hops_intra_1_3,
					2: hops_intra_2_3,
					5: hops_intra_3_5,
				},
			},
			5: {
				Intra: map[iface.ID]uint32{
					1: hops_intra_1_5,
					2: hops_intra_2_5,
					3: hops_intra_3_5,
				},
			},
		},
		Note: note,
	}
}

// TestParsing tests whether or not ParseStaticInfoCfg works properly.
func TestParsing(t *testing.T) {
	expected := getTestConfigData()
	actual, err := beaconing.ParseStaticInfoCfg("testdata/testconfigfile.json")
	assert.NoError(t, err, "error occurred during parsing")
	assert.Equal(t, expected, actual)
}

func TestGenerateStaticInfo(t *testing.T) {
	cfg := getTestConfigData()

	// "topology" information for a non-core AS:
	ifTypeNoncore := map[iface.ID]topology.LinkType{
		1: topology.Child,
		2: topology.Child,
		3: topology.Parent,
		5: topology.Peer,
	}
	// "topology" information for a core AS:
	ifTypeCore := map[iface.ID]topology.LinkType{
		1: topology.Core,
		2: topology.Child,
		3: topology.Core,
		5: topology.Core,
	}

	testCases := []struct {
		name     string
		ingress  iface.ID
		egress   iface.ID
		ifType   map[iface.ID]topology.LinkType
		expected staticinfo.Extension
	}{
		{
			name:    "propagate 3 -> 1",
			ingress: 3,
			egress:  1,
			ifType:  ifTypeNoncore,
			expected: staticinfo.Extension{
				Latency: staticinfo.LatencyInfo{
					Intra: map[iface.ID]time.Duration{
						2: latency_intra_1_2,
						3: latency_intra_1_3,
						5: latency_intra_1_5,
					},
					Inter: map[iface.ID]time.Duration{
						1: latency_inter_1,
						5: latency_inter_5,
					},
				},
				Bandwidth: staticinfo.BandwidthInfo{
					Intra: map[iface.ID]uint64{
						2: bandwidth_intra_1_2,
						3: bandwidth_intra_1_3,
						5: bandwidth_intra_1_5,
					},
					Inter: map[iface.ID]uint64{
						1: bandwidth_inter_1,
						5: bandwidth_inter_5,
					},
				},
				Geo: staticinfo.GeoInfo{
					1: geo_1,
					3: geo_3,
					5: geo_5,
				},
				LinkType: staticinfo.LinkTypeInfo{
					1: link_type_1,
					5: link_type_5,
				},
				InternalHops: map[iface.ID]uint32{
					2: hops_intra_1_2,
					3: hops_intra_1_3,
					5: hops_intra_1_5,
				},
				Note: note,
			},
		},
		{
			name:    "propagate 3 -> 2",
			ingress: 3,
			egress:  2,
			ifType:  ifTypeNoncore,
			expected: staticinfo.Extension{
				Latency: staticinfo.LatencyInfo{
					Intra: map[iface.ID]time.Duration{
						3: latency_intra_2_3,
						5: latency_intra_2_5,
					},
					Inter: map[iface.ID]time.Duration{
						2: latency_inter_2,
						5: latency_inter_5,
					},
				},
				Bandwidth: staticinfo.BandwidthInfo{
					Intra: map[iface.ID]uint64{
						3: bandwidth_intra_2_3,
						5: bandwidth_intra_2_5,
					},
					Inter: map[iface.ID]uint64{
						2: bandwidth_inter_2,
						5: bandwidth_inter_5,
					},
				},
				Geo: staticinfo.GeoInfo{
					2: geo_2,
					3: geo_3,
					5: geo_5,
				},
				LinkType: staticinfo.LinkTypeInfo{
					2: link_type_2,
					5: link_type_5,
				},
				InternalHops: map[iface.ID]uint32{
					3: hops_intra_2_3,
					5: hops_intra_2_5,
				},
				Note: note,
			},
		},
		{
			name:    "terminate",
			ingress: 3,
			egress:  0,
			ifType:  ifTypeNoncore,
			expected: staticinfo.Extension{
				Latency: staticinfo.LatencyInfo{
					Intra: map[iface.ID]time.Duration{},
					Inter: map[iface.ID]time.Duration{
						5: latency_inter_5,
					},
				},
				Bandwidth: staticinfo.BandwidthInfo{
					Intra: map[iface.ID]uint64{},
					Inter: map[iface.ID]uint64{
						5: bandwidth_inter_5,
					},
				},
				Geo: staticinfo.GeoInfo{
					3: geo_3,
					5: geo_5,
				},
				LinkType: staticinfo.LinkTypeInfo{
					5: link_type_5,
				},
				InternalHops: map[iface.ID]uint32{},
				Note:         note,
			},
		},
		{
			name:    "originate 1",
			ingress: 0,
			egress:  1,
			ifType:  ifTypeNoncore,
			expected: staticinfo.Extension{
				Latency: staticinfo.LatencyInfo{
					Intra: map[iface.ID]time.Duration{
						2: latency_intra_1_2,
						5: latency_intra_1_5,
					},
					Inter: map[iface.ID]time.Duration{
						1: latency_inter_1,
						5: latency_inter_5,
					},
				},
				Bandwidth: staticinfo.BandwidthInfo{
					Intra: map[iface.ID]uint64{
						2: bandwidth_intra_1_2,
						5: bandwidth_intra_1_5,
					},
					Inter: map[iface.ID]uint64{
						1: bandwidth_inter_1,
						5: bandwidth_inter_5,
					},
				},
				Geo: staticinfo.GeoInfo{
					1: geo_1,
					5: geo_5,
				},
				LinkType: staticinfo.LinkTypeInfo{
					1: link_type_1,
					5: link_type_5,
				},
				InternalHops: map[iface.ID]uint32{
					2: hops_intra_1_2,
					5: hops_intra_1_5,
				},
				Note: note,
			},
		},
		{
			name:    "originate 2",
			ingress: 0,
			egress:  2,
			ifType:  ifTypeNoncore,
			expected: staticinfo.Extension{
				Latency: staticinfo.LatencyInfo{
					Intra: map[iface.ID]time.Duration{
						5: latency_intra_2_5,
					},
					Inter: map[iface.ID]time.Duration{
						2: latency_inter_2,
						5: latency_inter_5,
					},
				},
				Bandwidth: staticinfo.BandwidthInfo{
					Intra: map[iface.ID]uint64{
						5: bandwidth_intra_2_5,
					},
					Inter: map[iface.ID]uint64{
						2: bandwidth_inter_2,
						5: bandwidth_inter_5,
					},
				},
				Geo: staticinfo.GeoInfo{
					2: geo_2,
					5: geo_5,
				},
				LinkType: staticinfo.LinkTypeInfo{
					2: link_type_2,
					5: link_type_5,
				},
				InternalHops: map[iface.ID]uint32{
					5: hops_intra_2_5,
				},
				Note: note,
			},
		},
		{
			name:    "core originate child 2",
			ingress: 0,
			egress:  2,
			ifType:  ifTypeCore,
			expected: staticinfo.Extension{
				Latency: staticinfo.LatencyInfo{
					Intra: map[iface.ID]time.Duration{
						1: latency_intra_1_2,
						3: latency_intra_2_3,
						5: latency_intra_2_5,
					},
					Inter: map[iface.ID]time.Duration{
						2: latency_inter_2,
					},
				},
				Bandwidth: staticinfo.BandwidthInfo{
					Intra: map[iface.ID]uint64{
						1: bandwidth_intra_1_2,
						3: bandwidth_intra_2_3,
						5: bandwidth_intra_2_5,
					},
					Inter: map[iface.ID]uint64{
						2: bandwidth_inter_2,
					},
				},
				Geo: staticinfo.GeoInfo{
					2: geo_2,
				},
				LinkType: staticinfo.LinkTypeInfo{
					2: link_type_2,
				},
				InternalHops: map[iface.ID]uint32{
					1: hops_intra_1_2,
					3: hops_intra_2_3,
					5: hops_intra_2_5,
				},
				Note: note,
			},
		},
		{
			name:    "core originate core neighbor 1",
			ingress: 0,
			egress:  1,
			ifType:  ifTypeCore,
			expected: staticinfo.Extension{
				Latency: staticinfo.LatencyInfo{
					Intra: map[iface.ID]time.Duration{},
					Inter: map[iface.ID]time.Duration{
						1: latency_inter_1,
					},
				},
				Bandwidth: staticinfo.BandwidthInfo{
					Intra: map[iface.ID]uint64{},
					Inter: map[iface.ID]uint64{
						1: bandwidth_inter_1,
					},
				},
				Geo: staticinfo.GeoInfo{
					1: geo_1,
				},
				LinkType: staticinfo.LinkTypeInfo{
					1: link_type_1,
				},
				InternalHops: map[iface.ID]uint32{},
				Note:         note,
			},
		},
		{
			name:    "core propagate 3 -> 1",
			ingress: 3,
			egress:  1,
			ifType:  ifTypeCore,
			expected: staticinfo.Extension{
				Latency: staticinfo.LatencyInfo{
					Intra: map[iface.ID]time.Duration{
						3: latency_intra_1_3,
					},
					Inter: map[iface.ID]time.Duration{
						1: latency_inter_1,
					},
				},
				Bandwidth: staticinfo.BandwidthInfo{
					Intra: map[iface.ID]uint64{
						3: bandwidth_intra_1_3,
					},
					Inter: map[iface.ID]uint64{
						1: bandwidth_inter_1,
					},
				},
				Geo: staticinfo.GeoInfo{
					1: geo_1,
					3: geo_3,
				},
				LinkType: staticinfo.LinkTypeInfo{
					1: link_type_1,
				},
				InternalHops: map[iface.ID]uint32{
					3: hops_intra_1_3,
				},
				Note: note,
			},
		},
		{
			name:    "core terminate",
			ingress: 3,
			egress:  0,
			ifType:  ifTypeCore,
			expected: staticinfo.Extension{
				Latency: staticinfo.LatencyInfo{
					Intra: map[iface.ID]time.Duration{},
					Inter: map[iface.ID]time.Duration{},
				},
				Bandwidth: staticinfo.BandwidthInfo{
					Intra: map[iface.ID]uint64{},
					Inter: map[iface.ID]uint64{},
				},
				Geo: staticinfo.GeoInfo{
					3: geo_3,
				},
				LinkType:     staticinfo.LinkTypeInfo{},
				InternalHops: map[iface.ID]uint32{},
				Note:         note,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := cfg.TestGenerate(tc.ifType, tc.ingress, tc.egress)
			assert.Equal(t, tc.expected, *actual)
		})
	}
}
