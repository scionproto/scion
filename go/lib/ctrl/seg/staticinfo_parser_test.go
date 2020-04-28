package seg

import (
	"strconv"
	"testing"
)

type ConfigTest struct {
	configData Configdata
	peers      map[uint16]bool
	egIfid     uint16
	inIfid     uint16
	expected   StaticInfoExtn
}

func compareConfigLatency(totest map[uint16]Latintf, expected map[uint16]Latintf) (bool, string) {
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

func compareConfigBW(totest map[uint16]Bwintf, expected map[uint16]Bwintf) (bool, string) {
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

func compareConfigLinktype(totest map[uint16]string, expected map[uint16]string) (bool, string) {
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

func compareConfigGeo(totest map[uint16]Geointf, expected map[uint16]Geointf) (bool, string) {
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

func compareConfigHops(totest map[uint16]Hopintf, expected map[uint16]Hopintf) (bool, string) {
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

// configcompare compares two Configdata, one under test (totest) and one with the expected result,
// and reports any deviations from the expected result in totest.
func configcompare(totest Configdata, expected Configdata) (bool, string) {
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

// testparsing tests whether or not Parseconfigdata works properly.
func TestParsing(t *testing.T) {
	var info string
	var passed bool
	totest, err := Parsenconfigdata("go/lib/ctrl/seg/staticinfo_testdta/testconfigfile.json")
	if err != nil {
		t.Error("Error occured during parsing: " + err.Error())
	}
	expected := Configdata{
		Latency: map[uint16]Latintf{
			1: {
				Inter: 30,
				Intra: map[uint16]uint16{2: 10, 3: 20, 5: 30},
			},
			2: {
				Inter: 40,
				Intra: map[uint16]uint16{1: 10, 3: 70, 5: 50},
			},
			3: {
				Inter: 80,
				Intra: map[uint16]uint16{1: 20, 2: 70, 5: 60},
			},
			5: {
				Inter: 90,
				Intra: map[uint16]uint16{1: 30, 2: 50, 3: 60},
			},
		},
		Bandwidth: map[uint16]Bwintf{
			1: {
				Inter: 400000000,
				Intra: map[uint16]uint32{2: 100000000, 3: 200000000, 5: 300000000},
			},
			2: {
				Inter: 5000000,
				Intra: map[uint16]uint32{1: 5044444, 3: 6555550, 5: 75555550},
			},
			3: {
				Inter: 80,
				Intra: map[uint16]uint32{1: 9333330, 2: 1044440, 5: 1333310},
			},
			5: {
				Inter: 120,
				Intra: map[uint16]uint32{1: 1333330, 2: 1555540, 3: 15666660},
			},
		},
		Linktype: map[uint16]string{1: "direct", 2: "opennet", 3: "multihop", 5: "direct"},
		Geo: map[uint16]Geointf{
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
		Hops: map[uint16]Hopintf{
			1: {
				Intra: map[uint16]uint8{2: 2, 3: 3, 5: 0},
			},
			2: {
				Intra: map[uint16]uint8{1: 2, 3: 3, 5: 1},
			},
			3: {
				Intra: map[uint16]uint8{1: 4, 2: 6, 5: 3},
			},
			5: {
				Intra: map[uint16]uint8{1: 2, 2: 3, 3: 4},
			},
		},
		Note: "asdf",
	}
	passed, info = configcompare(totest, expected)
	if !passed {
		t.Error(info)
	}
}

func compareLatencyInfo(totest LatencyInfo, expected LatencyInfo) (bool, string) {
	passed := true
	info := ""
	if !(totest.Egresslatency == expected.Egresslatency) {
		passed = false
		info += "Failed to get correct Egresslatency\n"
		info += "Expected: " + strconv.Itoa(int(expected.Egresslatency)) + ", got: " + strconv.Itoa(int(totest.Egresslatency)) + "\n"
	}
	if !(totest.Intooutlatency == expected.Intooutlatency) {
		passed = false
		info += "Failed to get correct Intooutlatency\n"
		info += "Expected: " + strconv.Itoa(int(expected.Intooutlatency)) + ", got: " + strconv.Itoa(int(totest.Intooutlatency)) + "\n"
	}
	for i := 0; i < len(totest.Childlatencies); i++ {
		temp := false
		for j := 0; j < len(expected.Childlatencies); j++ {
			if (totest.Childlatencies[i].Interface == expected.Childlatencies[j].Interface) && (totest.Childlatencies[i].Intradelay == expected.Childlatencies[j].Intradelay) {
				temp = true
			}
		}
		passed = passed && temp
		if !temp {
			info += "Failed to get correct Childlatency for interface " + strconv.Itoa(int(totest.Childlatencies[i].Interface)) + "\n"
			info += "Expected: " + strconv.Itoa(int(expected.Childlatencies[i].Intradelay)) + ", got: " + strconv.Itoa(int(totest.Childlatencies[i].Intradelay)) + "\n"
		}
	}
	for i := 0; i < len(totest.Peeringlatencies); i++ {
		temp := false
		for j := 0; j < len(expected.Peeringlatencies); j++ {
			if (totest.Peeringlatencies[i].IntfID == expected.Peeringlatencies[j].IntfID) && (totest.Peeringlatencies[i].IntraDelay == expected.Peeringlatencies[j].IntraDelay) && (totest.Peeringlatencies[i].Interdelay == expected.Peeringlatencies[j].Interdelay) {
				temp = true
			}
		}
		passed = passed && temp
		if !temp {
			info += "Failed to get correct Peeringlatencies for interface " + strconv.Itoa(int(totest.Peeringlatencies[i].IntfID)) + "\n"
			info += "Expected: " + strconv.Itoa(int(expected.Peeringlatencies[i].Interdelay)) + " " + strconv.Itoa(int(expected.Peeringlatencies[i].IntraDelay)) + ", got: " + strconv.Itoa(int(totest.Peeringlatencies[i].Interdelay)) + " " + strconv.Itoa(int(totest.Peeringlatencies[i].IntraDelay)) + "\n"
		}
	}
	return passed, info
}

func compareBWInfo(totest BandwidthInfo, expected BandwidthInfo) (bool, string) {
	passed := true
	info := ""

	if !(totest.EgressBW == expected.EgressBW) {
		passed = false
		info += "Failed to get correct EgressBW\n"
		info += "Expected: " + strconv.Itoa(int(expected.EgressBW)) + ", got: " + strconv.Itoa(int(totest.EgressBW)) + "\n"
	}
	if !(totest.IntooutBW == expected.IntooutBW) {
		passed = false
		info += "Failed to get correct IntooutBW\n"
		info += "Expected: " + strconv.Itoa(int(expected.IntooutBW)) + ", got: " + strconv.Itoa(int(totest.IntooutBW)) + "\n"
	}
	for i := 0; i < len(totest.BWPairs); i++ {
		temp := false
		for j := 0; j < len(expected.BWPairs); j++ {
			if (totest.BWPairs[i].IntfID == expected.BWPairs[j].IntfID) && (totest.BWPairs[i].BW == expected.BWPairs[j].BW) {
				temp = true
			}
		}
		passed = passed && temp
		if !temp {
			info += "Failed to get correct bandwidth for interface " + strconv.Itoa(int(totest.BWPairs[i].IntfID)) + "\n"
			info += "Expected: " + strconv.Itoa(int(expected.BWPairs[i].BW)) + ", got: " + strconv.Itoa(int(totest.BWPairs[i].BW)) + "\n"
		}
	}

	return passed, info
}

func compareGeoInfo(totest GeoInfo, expected GeoInfo) (bool, string) {
	passed := true
	info := ""

	for i := 0; i < len(totest.Locations); i++ {
		temp := false
		for j := 0; j < len(expected.Locations); j++ {
			if (totest.Locations[i].GPSData.Longitude == expected.Locations[j].GPSData.Longitude) && (totest.Locations[i].GPSData.Latitude == expected.Locations[j].GPSData.Latitude) && (totest.Locations[i].GPSData.Address == expected.Locations[j].GPSData.Address) {
				temp = true
				for k := 0; k < len(totest.Locations[i].IntfIDs); k++ {
					subtemp := false
					for l := 0; l < len(expected.Locations[i].IntfIDs); l++ {
						if totest.Locations[i].IntfIDs[k] == expected.Locations[j].IntfIDs[l] {
							subtemp = true
						}
					}
					if !subtemp {
						info += "Failed to get correct Location assignment for interface " + strconv.Itoa(int(totest.Locations[i].IntfIDs[k])) + "\n"
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

func compareLinktypeInfo(totest LinktypeInfo, expected LinktypeInfo) (bool, string) {
	passed := true
	info := ""

	if !(totest.EgressLT == expected.EgressLT) {
		passed = false
		info += "Failed to get correct EgressLT\n"
		info += "Expected: " + expected.EgressLT + ", got: " + totest.EgressLT + "\n"
	}
	for i := 0; i < len(totest.Peeringlinks); i++ {
		temp := false
		for j := 0; j < len(expected.Peeringlinks); j++ {
			if (totest.Peeringlinks[i].IntfID == expected.Peeringlinks[j].IntfID) && (totest.Peeringlinks[i].IntfLT == expected.Peeringlinks[j].IntfLT) {
				temp = true
			}
		}
		passed = passed && temp
		if !temp {
			info += "Failed to get correct linktype for interface " + strconv.Itoa(int(totest.Peeringlinks[i].IntfID)) + "\n"
			info += "Expected: " + expected.Peeringlinks[i].IntfLT + ", got: " + totest.Peeringlinks[i].IntfLT + "\n"
		}
	}

	return passed, info
}

func compareHopsInfo(totest InternalHopsInfo, expected InternalHopsInfo) (bool, string) {
	passed := true
	info := ""

	if !(totest.Intououthops == expected.Intououthops) {
		passed = false
		info += "Failed to get correct Intoouthops\n"
		info += "Expected: " + strconv.Itoa(int(expected.Intououthops)) + ", got: " + strconv.Itoa(int(totest.Intououthops)) + "\n"
	}
	for i := 0; i < len(totest.Hoppairs); i++ {
		temp := false
		for j := 0; j < len(expected.Hoppairs); j++ {
			if (totest.Hoppairs[i].IntfID == expected.Hoppairs[j].IntfID) && (totest.Hoppairs[i].Hops == expected.Hoppairs[j].Hops) {
				temp = true
			}
		}
		passed = passed && temp
		if !temp {
			info += "Failed to get correct hops for interface " + strconv.Itoa(int(totest.Hoppairs[i].IntfID)) + "\n"
			info += "Expected: " + strconv.Itoa(int(expected.Hoppairs[i].Hops)) + ", got: " + strconv.Itoa(int(totest.Hoppairs[i].Hops)) + "\n"
		}
	}

	return passed, info
}

// compareStaticinfo compares two StaticInfoExtns, one under test (totest) and one with the expected result,
// and reports any deviations from the expected result in totest.
func compareStaticinfo(totest, expected StaticInfoExtn) (bool, string) {
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
		configData: Configdata{
			Latency: map[uint16]Latintf{
				1: {
					Inter: 30,
					Intra: map[uint16]uint16{2: 10, 3: 20, 5: 30},
				},
				2: {
					Inter: 40,
					Intra: map[uint16]uint16{1: 10, 3: 70, 5: 50},
				},
				3: {
					Inter: 80,
					Intra: map[uint16]uint16{1: 20, 2: 70, 5: 60},
				},
				5: {
					Inter: 90,
					Intra: map[uint16]uint16{1: 30, 2: 50, 3: 60},
				},
			},
			Bandwidth: map[uint16]Bwintf{
				1: {
					Inter: 400000000,
					Intra: map[uint16]uint32{2: 100000000, 3: 200000000, 5: 300000000},
				},
				2: {
					Inter: 5000000,
					Intra: map[uint16]uint32{1: 5044444, 3: 6555550, 5: 75555550},
				},
				3: {
					Inter: 80,
					Intra: map[uint16]uint32{1: 9333330, 2: 1044440, 5: 1333310},
				},
				5: {
					Inter: 120,
					Intra: map[uint16]uint32{1: 1333330, 2: 1555540, 3: 15666660},
				},
			},
			Linktype: map[uint16]string{1: "direct", 2: "opennet", 3: "multihop", 5: "direct"},
			Geo: map[uint16]Geointf{
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
			Hops: map[uint16]Hopintf{
				1: {
					Intra: map[uint16]uint8{2: 2, 3: 3, 5: 0},
				},
				2: {
					Intra: map[uint16]uint8{1: 2, 3: 3, 5: 1},
				},
				3: {
					Intra: map[uint16]uint8{1: 4, 2: 6, 5: 3},
				},
				5: {
					Intra: map[uint16]uint8{1: 2, 2: 3, 3: 4},
				},
			},
			Note: "asdf",
		},
		peers:  map[uint16]bool{1: false, 2: false, 3: false, 5: true},
		egIfid: 2,
		inIfid: 3,
		expected: StaticInfoExtn{
			Latency: LatencyInfo{
				Egresslatency:  40,
				Intooutlatency: 70,
				Childlatencies: []Latencychildpair{
					{
						Intradelay: 70,
						Interface:  3,
					},
				},
				Peeringlatencies: []Latencypeeringtriplet{
					{
						Interdelay: 90,
						IntraDelay: 50,
						IntfID:     5,
					},
				},
			},
			Geo: GeoInfo{
				Locations: []Location{
					{
						GPSData: Coordinates{
							Latitude:  47.2,
							Longitude: 62.2,
							Address:   "geo1",
						},
						IntfIDs: []uint16{1},
					},
					{
						GPSData: Coordinates{
							Latitude:  79.2,
							Longitude: 45.2,
							Address:   "geo2",
						},
						IntfIDs: []uint16{2},
					},
					{
						GPSData: Coordinates{
							Latitude:  47.22,
							Longitude: 42.23,
							Address:   "geo3",
						},
						IntfIDs: []uint16{3},
					},
					{
						GPSData: Coordinates{
							Latitude:  48.2,
							Longitude: 46.2,
							Address:   "geo5",
						},
						IntfIDs: []uint16{5},
					},
				},
			},
			Linktype: LinktypeInfo{
				EgressLT: "opennet",
				Peeringlinks: []LTPeeringpair{
					{
						IntfID: 5,
						IntfLT: "direct",
					},
				},
			},
			Bandwidth: BandwidthInfo{
				EgressBW:  5000000,
				IntooutBW: 6555550,
				BWPairs: []BWPair{
					{
						IntfID: 3,
						BW:     6555550,
					},
					{
						IntfID: 5,
						BW:     120,
					},
				},
			},
			Hops: InternalHopsInfo{
				Intououthops: 3,
				Hoppairs: []Hoppair{
					{
						IntfID: 3,
						Hops:   3,
					},
					{
						IntfID: 5,
						Hops:   1,
					},
				},
			},
			Note: "asdf",
		},
	})
	passed := true
	for i := 0; i < len(testcases); i++ {

		data := GenerateStaticinfo(testcases[i].configData, testcases[i].peers, testcases[i].egIfid, testcases[i].inIfid)
		testres, testinfo := compareStaticinfo(data, testcases[i].expected)
		passed = passed && testres
		if !testres {
			t.Error(testinfo)
		}
	}
}
