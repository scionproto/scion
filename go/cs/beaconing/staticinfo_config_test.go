package beaconing

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
)

type ConfigTest struct {
	configData StaticInfoCfg
	peers      map[common.IFIDType]bool
	egIfid     common.IFIDType
	inIfid     common.IFIDType
	expected   seg.StaticInfoExtn
}

func getTestConfigData() StaticInfoCfg {
	return StaticInfoCfg{
		Latency: map[common.IFIDType]InterfaceLatencies{
			1: {
				Inter: 30,
				Intra: map[common.IFIDType]uint16{2: 10, 3: 20, 5: 30},
			},
			2: {
				Inter: 40,
				Intra: map[common.IFIDType]uint16{1: 10, 3: 70, 5: 50},
			},
			3: {
				Inter: 80,
				Intra: map[common.IFIDType]uint16{1: 20, 2: 70, 5: 60},
			},
			5: {
				Inter: 90,
				Intra: map[common.IFIDType]uint16{1: 30, 2: 50, 3: 60},
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
		Linktype: map[common.IFIDType]string{1: "direct", 2: "opennet", 3: "multihop", 5: "direct"},
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
				Intra: map[common.IFIDType]uint8{2: 2, 3: 3, 5: 0},
			},
			2: {
				Intra: map[common.IFIDType]uint8{1: 2, 3: 3, 5: 1},
			},
			3: {
				Intra: map[common.IFIDType]uint8{1: 4, 2: 6, 5: 3},
			},
			5: {
				Intra: map[common.IFIDType]uint8{1: 2, 2: 3, 3: 4},
			},
		},
		Note: "asdf",
	}
}

// TestParsing tests whether or not Parseconfigdata works properly.
func TestParsing(t *testing.T) {
	// var info string
	var passed bool
	totest, err := ParseStaticInfoCfg("testdata/testconfigfile.json")
	if err != nil {
		t.Error("Error occurred during parsing: " + err.Error())
	}
	expected := getTestConfigData()
	// passed, info = configcompare(totest, expected)
	passed = assert.Equal(t, totest, expected)
	if !passed {
		t.Error("StaticInfoConfigData does not match")
	}
}

// TestGenerateStaticinfo tests whether or not GenerateStaticinfo works properly.
func TestGenerateStaticinfo(t *testing.T) {
	var testcases []ConfigTest
	testcases = append(testcases, ConfigTest{
		configData: getTestConfigData(),
		peers:      map[common.IFIDType]bool{1: false, 2: false, 3: false, 5: true},
		egIfid:     2,
		inIfid:     3,
		expected: seg.StaticInfoExtn{
			Latency: seg.LatencyInfo{
				Egresslatency:          40,
				IngressToEgressLatency: 70,
				Childlatencies: []seg.ChildLatency{
					{
						Intradelay: 70,
						IfID:       3,
					},
				},
				Peerlatencies: []seg.PeerLatency{
					{
						Interdelay: 90,
						IntraDelay: 50,
						IfID:       5,
					},
				},
			},
			Geo: seg.GeoInfo{
				Locations: []seg.Location{
					{
						GPSData: seg.Coordinates{
							Latitude:  47.2,
							Longitude: 62.2,
							Address:   "geo1",
						},
						IfIDs: []common.IFIDType{1},
					},
					{
						GPSData: seg.Coordinates{
							Latitude:  79.2,
							Longitude: 45.2,
							Address:   "geo2",
						},
						IfIDs: []common.IFIDType{2},
					},
					{
						GPSData: seg.Coordinates{
							Latitude:  47.22,
							Longitude: 42.23,
							Address:   "geo3",
						},
						IfIDs: []common.IFIDType{3},
					},
					{
						GPSData: seg.Coordinates{
							Latitude:  48.2,
							Longitude: 46.2,
							Address:   "geo5",
						},
						IfIDs: []common.IFIDType{5},
					},
				},
			},
			Linktype: seg.LinktypeInfo{
				EgressLinkType: 2,
				Peerlinks: []seg.InterfaceLinkType{
					{
						IfID:     5,
						LinkType: 0,
					},
				},
			},
			Bandwidth: seg.BandwidthInfo{
				EgressBW:          5000000,
				IngressToEgressBW: 6555550,
				Bandwidths: []seg.InterfaceBandwidth{
					{
						IfID: 3,
						BW:   6555550,
					},
					{
						IfID: 5,
						BW:   120,
					},
				},
			},
			Hops: seg.InternalHopsInfo{
				InToOutHops: 3,
				InterfaceHops: []seg.InterfaceHops{
					{
						IfID: 3,
						Hops: 3,
					},
					{
						IfID: 5,
						Hops: 1,
					},
				},
			},
			Note: "asdf",
		},
	})
	for i := 0; i < len(testcases); i++ {
		totest := GenerateStaticinfo(testcases[i].configData, testcases[i].peers,
			testcases[i].egIfid, testcases[i].inIfid)
		assert.Equal(t, totest.Latency.Egresslatency,
			testcases[i].expected.Latency.Egresslatency)
		assert.Equal(t, totest.Latency.IngressToEgressLatency,
			testcases[i].expected.Latency.IngressToEgressLatency)
		assert.ElementsMatch(t, totest.Latency.Childlatencies,
			testcases[i].expected.Latency.Childlatencies)
		assert.ElementsMatch(t, totest.Latency.Peerlatencies,
			testcases[i].expected.Latency.Peerlatencies)

		assert.Equal(t, totest.Bandwidth.IngressToEgressBW,
			testcases[i].expected.Bandwidth.IngressToEgressBW)
		assert.Equal(t, totest.Bandwidth.EgressBW, testcases[i].expected.Bandwidth.EgressBW)
		assert.ElementsMatch(t, totest.Bandwidth.Bandwidths,
			testcases[i].expected.Bandwidth.Bandwidths)

		assert.Equal(t, totest.Linktype.EgressLinkType,
			testcases[i].expected.Linktype.EgressLinkType)
		assert.ElementsMatch(t, totest.Linktype.Peerlinks,
			testcases[i].expected.Linktype.Peerlinks)

		assert.Equal(t, totest.Hops.InToOutHops,
			testcases[i].expected.Hops.InToOutHops)
		assert.ElementsMatch(t, totest.Hops.InterfaceHops,
			testcases[i].expected.Hops.InterfaceHops)

		assert.ElementsMatch(t, totest.Geo.Locations,
			testcases[i].expected.Geo.Locations)

		assert.Equal(t, totest.Note, testcases[i].expected.Note)

	}
}
