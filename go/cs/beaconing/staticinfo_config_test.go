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

package beaconing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/util"
)

func getTestConfigData() *StaticInfoCfg {

	ms := func(ms int) util.DurWrap {
		return util.DurWrap{Duration: time.Duration(ms) * time.Millisecond}
	}

	return &StaticInfoCfg{
		Latency: map[common.IFIDType]InterfaceLatencies{
			1: {
				Inter: ms(30),
				Intra: map[common.IFIDType]util.DurWrap{2: ms(10), 3: ms(20), 5: ms(30)},
			},
			2: {
				Inter: ms(40),
				Intra: map[common.IFIDType]util.DurWrap{1: ms(10), 3: ms(70), 5: ms(50)},
			},
			3: {
				Inter: ms(80),
				Intra: map[common.IFIDType]util.DurWrap{1: ms(20), 2: ms(70), 5: ms(60)},
			},
			5: {
				Inter: ms(90),
				Intra: map[common.IFIDType]util.DurWrap{1: ms(30), 2: ms(50), 3: ms(60)},
			},
		},
		Bandwidth: map[common.IFIDType]InterfaceBandwidths{
			1: {
				Inter: 400000000,
				Intra: map[common.IFIDType]uint32{2: 100000000, 3: 200000000, 5: 300000000},
			},
			2: {
				Inter: 5000000,
				Intra: map[common.IFIDType]uint32{1: 5044444, 3: 6555550, 5: 75555550},
			},
			3: {
				Inter: 80,
				Intra: map[common.IFIDType]uint32{1: 9333330, 2: 1044440, 5: 1333310},
			},
			5: {
				Inter: 120,
				Intra: map[common.IFIDType]uint32{1: 1333330, 2: 1555540, 3: 15666660},
			},
		},
		LinkType: map[common.IFIDType]LinkType{
			1: LinkType(seg.LinkTypeDirect),
			2: LinkType(seg.LinkTypeOpennet),
			3: LinkType(seg.LinkTypeMultihop),
			5: LinkType(seg.LinkTypeDirect),
		},
		Geo: map[common.IFIDType]InterfaceGeodata{
			1: {
				Longitude: 62.2,
				Latitude:  47.2,
				Address:   "geo1",
			},
			2: {
				Longitude: 45.2,
				Latitude:  79.2,
				Address:   "geo2",
			},
			3: {
				Longitude: 42.23,
				Latitude:  47.22,
				Address:   "geo3",
			},
			5: {
				Longitude: 46.2,
				Latitude:  48.2,
				Address:   "geo5",
			},
		},
		Hops: map[common.IFIDType]InterfaceHops{
			1: {
				Intra: map[common.IFIDType]uint32{2: 2, 3: 3, 5: 0},
			},
			2: {
				Intra: map[common.IFIDType]uint32{1: 2, 3: 3, 5: 1},
			},
			3: {
				Intra: map[common.IFIDType]uint32{1: 4, 2: 6, 5: 3},
			},
			5: {
				Intra: map[common.IFIDType]uint32{1: 2, 2: 3, 3: 4},
			},
		},
		Note: "asdf",
	}
}

// TestParsing tests whether or not ParseStaticInfoCfg works properly.
func TestParsing(t *testing.T) {
	expected := getTestConfigData()
	actual, err := ParseStaticInfoCfg("testdata/testconfigfile.json")
	assert.NoError(t, err, "error occurred during parsing")
	assert.Equal(t, expected, actual)
}

// TestGenerateStaticinfo tests whether or not GenerateStaticinfo works properly.
func TestGenerateStaticinfo(t *testing.T) {
	test := struct {
		configData *StaticInfoCfg
		peers      map[common.IFIDType]struct{}
		egIfid     common.IFIDType
		inIfid     common.IFIDType
		expected   seg.StaticInfoExtension
	}{
		configData: getTestConfigData(),
		peers:      map[common.IFIDType]struct{}{5: {}},
		egIfid:     2,
		inIfid:     3,
		expected: seg.StaticInfoExtension{
			Latency: &seg.LatencyInfo{
				Inter: 40 * time.Millisecond,
				Intra: 70 * time.Millisecond,
				XoverIntra: map[common.IFIDType]time.Duration{
					3: 70 * time.Millisecond,
					5: 50 * time.Millisecond,
				},
				PeerInter: map[common.IFIDType]time.Duration{
					5: 90 * time.Millisecond,
				},
			},
			Geo: seg.GeoInfo{
				1: seg.GeoCoordinates{
					Latitude:  47.2,
					Longitude: 62.2,
					Address:   "geo1",
				},
				2: seg.GeoCoordinates{
					Latitude:  79.2,
					Longitude: 45.2,
					Address:   "geo2",
				},
				3: seg.GeoCoordinates{
					Latitude:  47.22,
					Longitude: 42.23,
					Address:   "geo3",
				},
				5: seg.GeoCoordinates{
					Latitude:  48.2,
					Longitude: 46.2,
					Address:   "geo5",
				},
			},
			LinkType: seg.LinkTypeInfo{
				2: seg.LinkTypeOpennet,
				5: seg.LinkTypeDirect,
			},
			Bandwidth: &seg.BandwidthInfo{
				Inter: 5000000,
				Intra: 6555550,
				XoverIntra: map[common.IFIDType]uint32{
					3: 6555550,
					5: 75555550,
				},
				PeerInter: map[common.IFIDType]uint32{
					5: 120,
				},
			},
			InternalHops: &seg.InternalHopsInfo{
				Hops: 3,
				XoverHops: map[common.IFIDType]uint32{
					3: 3,
					5: 1,
				},
			},
			Note: "asdf",
		},
	}
	actual := test.configData.generateStaticinfo(test.peers, test.egIfid, test.inIfid)
	assert.Equal(t, test.expected, actual)
}
