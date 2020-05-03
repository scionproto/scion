package beaconing

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"

	"github.com/stretchr/testify/assert"
)

type ConfigTest struct {
	configData StaticInfoCfg
	peers      map[common.IFIDType]bool
	egIfid     common.IFIDType
	inIfid     common.IFIDType
	expected   seg.StaticInfoExtn
}

func compareConfigLatency(totest map[common.IFIDType]InterfaceLatencies, expected map[common.IFIDType]InterfaceLatencies) (bool, string) {
	passed := true
	info := ""

	for ifID, val := range totest {
		if val.Inter == expected[ifID].Inter {
			for subifID, subval := range val.Intra {
				if !(subval == expected[ifID].Intra[subifID]) {
					passed = false
					info += "Failed to parse latency value (intra): Interface" + strconv.Itoa(int(ifID)) + ", subinterface" + strconv.Itoa(int(subifID)) + "\n"
				}
			}
		} else {
			passed = false
			info += "Failed to parse latency value (inter): Interface" + strconv.Itoa(int(ifID)) + "\n"
		}
	}

	return passed, info
}

func compareConfigBW(totest map[common.IFIDType]InterfaceBandwidths, expected map[common.IFIDType]InterfaceBandwidths) (bool, string) {
	passed := true
	info := ""

	for ifID, val := range totest {
		if val.Inter == expected[ifID].Inter {
			for subifID, subval := range val.Intra {
				if !(subval == expected[ifID].Intra[subifID]) {
					passed = false
					info += "Failed to parse bandwidth value (intra): Interface" + strconv.Itoa(int(ifID)) + ", subinterface" + strconv.Itoa(int(subifID)) + "\n"
				}
			}
		} else {
			passed = false
			info += "Failed to parse bandwidth value (inter): Interface" + strconv.Itoa(int(ifID)) + "\n"
		}
	}

	return passed, info
}

func compareConfigLinktype(totest map[common.IFIDType]string, expected map[common.IFIDType]string) (bool, string) {
	passed := true
	info := ""

	for ifID, val := range totest {
		if !(val == expected[ifID]) {
			passed = false
			info += "Failed to parse linktype value: Interface" + strconv.Itoa(int(ifID)) + "\n"
		}
	}

	return passed, info
}

func compareConfigGeo(totest map[common.IFIDType]InterfaceGeodata, expected map[common.IFIDType]InterfaceGeodata) (bool, string) {
	passed := true
	info := ""

	for ifID, val := range totest {
		if !((val.Longitude == expected[ifID].Longitude) && (val.Latitude == expected[ifID].Latitude) && (val.Address == expected[ifID].Address)) {
			passed = false
			info += "Failed to parse geo value: Interface" + strconv.Itoa(int(ifID)) + "\n"
		}
	}

	return passed, info
}

func compareConfigHops(totest map[common.IFIDType]InterfaceHops, expected map[common.IFIDType]InterfaceHops) (bool, string) {
	passed := true
	info := ""

	for ifID, val := range totest {
		for subifID, subval := range val.Intra {
			if !(subval == expected[ifID].Intra[subifID]) {
				passed = false
				info += "Failed to parse hops value: Interface" + strconv.Itoa(int(ifID)) + ", subinterface" + strconv.Itoa(int(subifID)) + "\n"
			}
		}
	}

	return passed, info
}

// configcompare compares two StaticInfoCfg, one under test (totest) and one with the expected result,
// and reports any deviations from the expected result in totest.
func configcompare(totest StaticInfoCfg, expected StaticInfoCfg) (bool, string) {
	passed := true
	var info string

	latencyres, latencyreport := compareConfigLatency(totest.Latency, expected.Latency)
	passed = passed && latencyres
	info += latencyreport

	bwres, bwreport := compareConfigBW(totest.Bandwidth, expected.Bandwidth)
	passed = passed && bwres
	info += bwreport

	geores, georeport := compareConfigGeo(totest.Geo, expected.Geo)
	passed = passed && geores
	info += georeport

	linktyperes, linktypereport := compareConfigLinktype(totest.Linktype, expected.Linktype)
	passed = passed && linktyperes
	info += linktypereport

	hopres, hopreport := compareConfigHops(totest.Hops, expected.Hops)
	passed = passed && hopres
	info += hopreport

	if !(totest.Note == expected.Note) {
		passed = false
		info += "Failed to parse note\n"
	}

	return passed, info
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
		t.Error("Error occured during parsing: " + err.Error())
	}
	expected := getTestConfigData()
	// passed, info = configcompare(totest, expected)
	passed = assert.Equal(t, totest, expected)
	if !passed {
		t.Error("StaticInfoConfigData does not match")
	}
}

func compareLatencyInfo(totest seg.LatencyInfo, expected seg.LatencyInfo) (bool, string) {
	passed := true
	info := ""
	if !(totest.Egresslatency == expected.Egresslatency) {
		passed = false
		info += "Failed to get correct Egresslatency\n"
		info += "Expected: " + strconv.Itoa(int(expected.Egresslatency)) + ", got: " + strconv.Itoa(int(totest.Egresslatency)) + "\n"
	}
	if !(totest.IngressToEgressLatency == expected.IngressToEgressLatency) {
		passed = false
		info += "Failed to get correct IngressToEgressLatency\n"
		info += "Expected: " + strconv.Itoa(int(expected.IngressToEgressLatency)) + ", got: " + strconv.Itoa(int(totest.IngressToEgressLatency)) + "\n"
	}
	for i := 0; i < len(totest.Childlatencies); i++ {
		temp := false
		for j := 0; j < len(expected.Childlatencies); j++ {
			if (totest.Childlatencies[i].IfID == expected.Childlatencies[j].IfID) && (totest.Childlatencies[i].Intradelay == expected.Childlatencies[j].Intradelay) {
				temp = true
			}
		}
		passed = passed && temp
		if !temp {
			info += "Failed to get correct Childlatency for interface " + strconv.Itoa(int(totest.Childlatencies[i].IfID)) + "\n"
			info += "Expected: " + strconv.Itoa(int(expected.Childlatencies[i].Intradelay)) + ", got: " + strconv.Itoa(int(totest.Childlatencies[i].Intradelay)) + "\n"
		}
	}
	for i := 0; i < len(totest.Peerlatencies); i++ {
		temp := false
		for j := 0; j < len(expected.Peerlatencies); j++ {
			if (totest.Peerlatencies[i].IfID == expected.Peerlatencies[j].IfID) && (totest.Peerlatencies[i].IntraDelay == expected.Peerlatencies[j].IntraDelay) && (totest.Peerlatencies[i].Interdelay == expected.Peerlatencies[j].Interdelay) {
				temp = true
			}
		}
		passed = passed && temp
		if !temp {
			info += "Failed to get correct Peeringlatencies for interface " + strconv.Itoa(int(totest.Peerlatencies[i].IfID)) + "\n"
			info += "Expected: " + strconv.Itoa(int(expected.Peerlatencies[i].Interdelay)) + " " + strconv.Itoa(int(expected.Peerlatencies[i].IntraDelay)) + ", got: " + strconv.Itoa(int(totest.Peerlatencies[i].Interdelay)) + " " + strconv.Itoa(int(totest.Peerlatencies[i].IntraDelay)) + "\n"
		}
	}
	return passed, info
}

func compareBWInfo(totest seg.BandwidthInfo, expected seg.BandwidthInfo) (bool, string) {
	passed := true
	info := ""

	if !(totest.EgressBW == expected.EgressBW) {
		passed = false
		info += "Failed to get correct EgressBW\n"
		info += "Expected: " + strconv.Itoa(int(expected.EgressBW)) + ", got: " + strconv.Itoa(int(totest.EgressBW)) + "\n"
	}
	if !(totest.IngressToEgressBW == expected.IngressToEgressBW) {
		passed = false
		info += "Failed to get correct IntooutBW\n"
		info += "Expected: " + strconv.Itoa(int(expected.IngressToEgressBW)) + ", got: " + strconv.Itoa(int(totest.IngressToEgressBW)) + "\n"
	}
	for i := 0; i < len(totest.Bandwidths); i++ {
		temp := false
		for j := 0; j < len(expected.Bandwidths); j++ {
			if (totest.Bandwidths[i].IfID == expected.Bandwidths[j].IfID) && (totest.Bandwidths[i].BW == expected.Bandwidths[j].BW) {
				temp = true
			}
		}
		passed = passed && temp
		if !temp {
			info += "Failed to get correct bandwidth for interface " + strconv.Itoa(int(totest.Bandwidths[i].IfID)) + "\n"
			info += "Expected: " + strconv.Itoa(int(expected.Bandwidths[i].BW)) + ", got: " + strconv.Itoa(int(totest.Bandwidths[i].BW)) + "\n"
		}
	}

	return passed, info
}

func compareGeoInfo(totest seg.GeoInfo, expected seg.GeoInfo) (bool, string) {
	passed := true
	info := ""

	for i := 0; i < len(totest.Locations); i++ {
		temp := false
		for j := 0; j < len(expected.Locations); j++ {
			if (totest.Locations[i].GPSData.Longitude == expected.Locations[j].GPSData.Longitude) && (totest.Locations[i].GPSData.Latitude == expected.Locations[j].GPSData.Latitude) && (totest.Locations[i].GPSData.Address == expected.Locations[j].GPSData.Address) {
				temp = true
				for k := 0; k < len(totest.Locations[i].IfIDs); k++ {
					subtemp := false
					for l := 0; l < len(expected.Locations[i].IfIDs); l++ {
						if totest.Locations[i].IfIDs[k] == expected.Locations[j].IfIDs[l] {
							subtemp = true
						}
					}
					if !subtemp {
						info += "Failed to get correct Location assignment for interface " + strconv.Itoa(int(totest.Locations[i].IfIDs[k])) + "\n"
					}
					temp = temp && subtemp
				}
			}
		}
		passed = passed && temp
		if !temp {
			info += "Failed to get correct Location for Location " + totest.Locations[i].GPSData.Address + "\n"
		}
	}

	return passed, info
}

func compareLinktypeInfo(totest seg.LinktypeInfo, expected seg.LinktypeInfo) (bool, string) {
	passed := true
	info := ""

	if !(totest.EgressLinkType == expected.EgressLinkType) {
		passed = false
		info += "Failed to get correct EgressLT\n"
		info += "Expected: " + strconv.Itoa(int(expected.EgressLinkType)) + ", got: " + strconv.Itoa(int(totest.EgressLinkType)) + "\n"
	}
	for i := 0; i < len(totest.Peerlinks); i++ {
		temp := false
		for j := 0; j < len(expected.Peerlinks); j++ {
			if (totest.Peerlinks[i].IfID == expected.Peerlinks[j].IfID) && (totest.Peerlinks[i].LinkType == expected.Peerlinks[j].LinkType) {
				temp = true
			}
		}
		passed = passed && temp
		if !temp {
			info += "Failed to get correct linktype for interface " + strconv.Itoa(int(totest.Peerlinks[i].IfID)) + "\n"
			info += "Expected: " + strconv.Itoa(int(expected.Peerlinks[i].LinkType)) + ", got: " + strconv.Itoa(int(totest.Peerlinks[i].LinkType)) + "\n"
		}
	}

	return passed, info
}

func compareHopsInfo(totest seg.InternalHopsInfo, expected seg.InternalHopsInfo) (bool, string) {
	passed := true
	info := ""

	if !(totest.InToOutHops == expected.InToOutHops) {
		passed = false
		info += "Failed to get correct Intoouthops\n"
		info += "Expected: " + strconv.Itoa(int(expected.InToOutHops)) + ", got: " + strconv.Itoa(int(totest.InToOutHops)) + "\n"
	}
	for i := 0; i < len(totest.InterfaceHops); i++ {
		temp := false
		for j := 0; j < len(expected.InterfaceHops); j++ {
			if (totest.InterfaceHops[i].IfID == expected.InterfaceHops[j].IfID) && (totest.InterfaceHops[i].Hops == expected.InterfaceHops[j].Hops) {
				temp = true
			}
		}
		passed = passed && temp
		if !temp {
			info += "Failed to get correct hops for interface " + strconv.Itoa(int(totest.InterfaceHops[i].IfID)) + "\n"
			info += "Expected: " + strconv.Itoa(int(expected.InterfaceHops[i].Hops)) + ", got: " + strconv.Itoa(int(totest.InterfaceHops[i].Hops)) + "\n"
		}
	}

	return passed, info
}

// compareStaticinfo compares two StaticInfoExtns, one under test (totest) and one with the expected result,
// and reports any deviations from the expected result in totest.
func compareStaticinfo(totest, expected seg.StaticInfoExtn) (bool, string) {
	passed := true
	var info string

	latencyres, latencyreport := compareLatencyInfo(totest.Latency, expected.Latency)
	passed = passed && latencyres
	info += latencyreport

	bwres, bwreport := compareBWInfo(totest.Bandwidth, expected.Bandwidth)
	passed = passed && bwres
	info += bwreport

	geores, georeport := compareGeoInfo(totest.Geo, expected.Geo)
	passed = passed && geores
	info += georeport

	linktyperes, linktypereport := compareLinktypeInfo(totest.Linktype, expected.Linktype)
	passed = passed && linktyperes
	info += linktypereport

	hopres, hopreport := compareHopsInfo(totest.Hops, expected.Hops)
	passed = passed && hopres
	info += hopreport

	if !(totest.Note == expected.Note) {
		passed = false
		info += "Failed to get correct Note\n"
	}

	return passed, info
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
	passed := true
	for i := 0; i < len(testcases); i++ {

		totest := GenerateStaticinfo(testcases[i].configData, testcases[i].peers, testcases[i].egIfid, testcases[i].inIfid)
		// testres, testinfo := compareStaticinfo(data, testcases[i].expected)
		testres2 := assert.Equal(t, totest, testcases[i].expected)
		testres1, testinfo := compareStaticinfo(totest, testcases[i].expected)
		if !testres2 {
			t.Error("StaticInfo does not match for testcase " + strconv.Itoa(i))
		}
		passed = passed && testres1
		if !testres1 {
			t.Error(testinfo)
		}
	}
	if !passed {
		t.Error("Test failed.")
	} else {
		fmt.Println("All clear.")
	}

}
