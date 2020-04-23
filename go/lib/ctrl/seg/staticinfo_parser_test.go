package seg

import (
	"strconv"
)

/*
type LatencyInfoTest struct {
	Egresslatency uint16 `json:"ExpEgress"`
	Intooutlatency uint16 `json:"ExpIO"`
	Childlatencies    []Latencychildpairtest `json:"ExpCL"`
	Peeringlatencies     []Latencypeeringtriplettest `json:"ExpPT"`
}

type Latencychildpairtest struct {
	Intradelay uint16   `json:"ExpIntra"`
	Interface  uint16 `json:"ExpIntf"`
}

type Latencypeeringtriplettest struct {
	Interdelay uint16 `json:"ExpInter"`
	IntraDelay uint16 `json:"ExpIntra"`
	IntfID uint16 `json:"ExpIntf"`
}

type BandwidthInfoTest struct {
	EgressBW uint32 `json:"ExpEgress"`
	IntooutBW uint32 `json:"ExpIO"`
	BWPairs []BWPairtest `json:"ExpBWP"`
}

type BWPairtest struct {
	BW  uint32   `json:"ExpBWV"`
	IntfID uint16 `json:"ExpIntf"`
}

type GeoInfoTest struct {
	Locations []Locationtest `json:"ExpLocs"`
}

type Locationtest struct {
	GPSData      Coordinatestest `json:"ExpGPS"`
	IntfIDs []uint16 `json:"ExpIntfs"`
}

type Coordinatestest struct {
	Latitude   float32 `json:"ExpLatitude"`
	Longitude   float32 `json:"ExpLongitude"`
	Address string  `json:"ExpAddr"`
}

type LinktypeInfoTest struct {
	EgressLT   string `json:"ExpEgress"`
	Peeringlinks  []LTPeeringpairtest `json:"ExpPL"`
}

type LTPeeringpairtest struct {
	IntfID uint16 `json:"ExpIntf"`
	IntfLT string `json:"ExpLT"`
}

type InternalHopsInfoTest struct {
	Intououthops uint8 `json:"ExpIO"`
	Hoppairs []Hoppairtest `json:"ExpHP"`
}

type Hoppairtest struct {
	Hops uint8    `json:"ExpHops"`
	IntfID uint16 `json:"ExpIntf"`
}

// Struct used to parse data from expected.json (json file containing expected results)
type Test struct {
	EgIFID uint16           `json:"Egress"`
	InIFID uint16           `json:"Ingress"`
	LI LatencyInfoTest      `json:"ExpLatency"`
	GI GeoInfoTest          `json:"ExpGeo"`
	LT LinktypeInfoTest     `json:"ExpLT"`
	BW BandwidthInfoTest    `json:"ExpBW"`
	IH InternalHopsInfoTest `json:"ExpIH"`
	NI string               `json:"ExpNI"`
}

type Testdata struct {
	Tests []Test `json:"Tests"`
}


// Takes a Test struct and a StaticInfoExtn to be tested.
// Compares the values in the two structs (ignores order in arrays).
// Returns a bool indicating whether the two structs contain the same data and a string. If they do,
// the string is empty, otherwise it specifies where they differ.
func dochecks(test Test, totest StaticInfoExtn) (bool, string) {
	retstr := ""
	res := true
	tempres := true
	subtempres := false
	res = res && (test.LI.Intooutlatency == totest.Latency.Intooutlatency) && (test.LI.Egresslatency == totest.Latency.Egresslatency)
	for _, pair := range totest.Latency.Childlatencies{
		for _, subpair := range test.LI.Childlatencies {
			subtempres = subtempres || ((pair.Intradelay == subpair.Intradelay) && (pair.Interface == subpair.Interface))
		}
		if !subtempres {
			retstr += ("Latency, IntfID: " + strconv.Itoa(int(pair.Interface)) + "\n")
		}
		tempres = tempres && subtempres
		subtempres = false
	}
	res = res && tempres
	tempres = true

	for _, pair := range totest.Latency.Peeringlatencies{
		for _, subpair := range test.LI.Peeringlatencies{
			subtempres = subtempres || ((pair.IntraDelay == subpair.IntraDelay) && (pair.Interdelay == subpair.Interdelay) && (pair.IntfID == subpair.IntfID))
		}
		if !subtempres {
			retstr += ("Latency, IntfID: " + strconv.Itoa(int(pair.IntfID)) + "\n")
		}
		tempres = tempres && subtempres
		subtempres = false
	}
	res = res && tempres
	tempres = true

	res = res && (test.BW.IntooutBW == totest.Bandwidth.IntooutBW) && (test.BW.EgressBW == totest.Bandwidth.EgressBW)
	for _, pair := range totest.Bandwidth.BWPairs{
		for _, subpair := range test.BW.BWPairs{
			subtempres = subtempres || ((pair.BW == subpair.BW) && (pair.IntfID == subpair.IntfID))
		}
		if !subtempres {
			retstr += ("Bandwidth, IntfID: " + strconv.Itoa(int(pair.IntfID)) + "\n")
		}
		tempres = tempres && subtempres
		subtempres = false
	}
	res = res && tempres
	tempres = true

	res = res && (test.LT.EgressLT == totest.Linktype.EgressLT)
	for _, pair := range totest.Linktype.Peeringlinks {
		for _, subpair := range test.LT.Peeringlinks{
			subtempres = subtempres || ((pair.IntfLT == subpair.IntfLT) && (pair.IntfID == subpair.IntfID))
		}
		if !subtempres {
			retstr += ("Linktype, IntfID: " + strconv.Itoa(int(pair.IntfID)) + "\n")
		}
		tempres = tempres && subtempres
		subtempres = false
	}
	res = res && tempres
	tempres = true

	for _, loc := range totest.Geo.Locations {
		for _, subloc := range test.GI.Locations{
			if (loc.GPSData.Longitude == subloc.GPSData.Longitude) && (loc.GPSData.Latitude == subloc.GPSData.Latitude) && (loc.GPSData.Address == subloc.GPSData.Address){
				for _, intf := range loc.IntfIDs{
					for _, subintf := range subloc.IntfIDs{
						subtempres = subtempres || (intf == subintf)
					}
					if !subtempres {
						longitude := fmt.Sprintf("%f", loc.GPSData.Longitude)
						latitude:= fmt.Sprintf("%f", loc.GPSData.Latitude)
						retstr += ("GPS, Location: " + longitude + " " + latitude + " " + loc.GPSData.Address + ", IntfID: " + strconv.Itoa(int(intf)) + "\n")
					}
					tempres = tempres && subtempres
					subtempres = false
				}
			}
		}
	}
	res = res && tempres
	tempres = true

	res = res && (test.IH.Intououthops == totest.Hops.Intououthops)
	for _, pair := range totest.Hops.Hoppairs{
		for _, subpair := range test.IH.Hoppairs{
			subtempres = subtempres || ((pair.Hops == subpair.Hops) && (pair.IntfID == subpair.IntfID))
		}
		if !subtempres {
			retstr += ("Hops, IntfID: " + strconv.Itoa(int(pair.IntfID)) + "\n")
		}
		tempres = tempres && subtempres
		subtempres = false
	}
	res = res && tempres

	res = res && (test.NI == totest.Note)

	if !(test.NI == totest.Note) {
		retstr += ("Note\n")
	}

	return res, retstr
}



// Takes an array of paths of config.json files, an array of paths of topologyfiles
// and the expected result of the test.
// Returns the test result.
func subtest(datafiles []string, topofiles []string, testdata string) (string, bool){
	if !(len(datafiles) == len(topofiles)){
		return "Error: Length of input arrays must match", false
	}
	jsonFile, err := os.Open(testdata)
	if err != nil {
		fmt.Println(err)
		return "Error: Failed to read testdata", false
	}
	defer jsonFile.Close()
	rawfile,_ := ioutil.ReadAll(jsonFile)
	var TD Testdata
	json.Unmarshal(rawfile, &TD)
	if (len(TD.Tests)!= len(datafiles)){
		return "Error: Number of tests must match length of input arrays", false
	}
	noerror := true
	var errmsg string
	for i,_ := range datafiles{
		ExpRes := TD.Tests[i]
		configdata, _ := parsenconfigdata(datafiles[i])
		totest := generateStaticinfo(configdata, ExpRes.EgIFID, ExpRes.InIFID)
		testpassed, specifics := dochecks(ExpRes, *totest)
		if !testpassed {
			errmsg = "Error: Test failed : " + strconv.Itoa(i+1) + " (indexed starting at 1)\n"
			errmsg += "Test failed for following interfaces:\n"
			errmsg += specifics
		}
		noerror = noerror && testpassed
	}

	if !noerror{
		return errmsg, false
	}
	return "All tests successful", true
}

// Takes no arguments.
// Does the test and returns the result.
// Probably doesn't work since I'm not sure how to properly specify filepaths.
func test() (string, bool){
	var datafiles []string
	var topofiles []string
	datafiles = append(datafiles, "testconfigfile.json")
	topofiles = append(topofiles, "topology.json")

	res1, res2 := subtest(datafiles, topofiles, "expected.json")
	return res1, res2
}
*/


func configcompare(totest, expected Configdata)(bool, string){
	passed := true
	var issue string
	for ifID, val := range totest.Latency{
		if (val.Inter == expected.Latency[ifID].Inter){
			for subifID, subval := range val.Intra{
				if(subval == expected.Latency[ifID].Intra[subifID]){
					passed = passed && true
				} else {
					passed = false
					issue += "Failed to parse latency value (intra): Interface" + strconv.Itoa(int(ifID)) + ", subinterface" + strconv.Itoa(int(subifID)) + "\n"
				}
			}
		} else {
			passed = false
			issue += "Failed to parse latency value (inter): Interface" + strconv.Itoa(int(ifID)) + "\n"
		}
	}
	for ifID, val := range totest.Bandwidth{
		if (val.Inter == expected.Bandwidth[ifID].Inter){
			for subifID, subval := range val.Intra{
				if(subval == expected.Bandwidth[ifID].Intra[subifID]){
					passed = passed && true
				} else {
					passed = false
					issue += "Failed to parse bandwidth value (intra): Interface" + strconv.Itoa(int(ifID)) + ", subinterface" + strconv.Itoa(int(subifID)) + "\n"
				}
			}
		} else {
			passed = false
			issue += "Failed to parse bandwidth value (inter): Interface" + strconv.Itoa(int(ifID)) + "\n"
		}
	}
	for ifID, val := range totest.Linktype{
		if (val == expected.Linktype[ifID]){
			passed = passed && true
		} else {
			passed = false
			issue += "Failed to parse linktype value: Interface" + strconv.Itoa(int(ifID)) + "\n"
		}
	}
	for ifID, val := range totest.Geo{
		if (val.Longitude == expected.Geo[ifID].Longitude) && (val.Latitude == expected.Geo[ifID].Latitude) && (val.Address == expected.Geo[ifID].Address) {
			passed = passed && true
		} else {
			passed = false
			issue += "Failed to parse geo value: Interface" + strconv.Itoa(int(ifID)) + "\n"
		}
	}
	for ifID, val := range totest.Hops{
		for subifID, subval := range val.Intra{
			if(subval == expected.Hops[ifID].Intra[subifID]){
				passed = passed && true
			} else {
				passed = false
				issue += "Failed to parse hops value: Interface" + strconv.Itoa(int(ifID)) + ", subinterface" + strconv.Itoa(int(subifID)) + "\n"
			}
		}
	}
	if (totest.Note == expected.Note){
		passed = passed && true
	} else {
		passed = false
		issue += "Failed to parse note\n"
	}

	return passed, issue
}



func testparsing() (string, bool){
	var info string
	var passed bool
	totest,err := Parsenconfigdata("staticinfo_testdta/testconfigfile.json")
	if err != nil {
		info = "Error occured during parsing: " + err.Error()
		return info, false
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
		Bandwidth:  map[uint16]Bwintf{
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
		Linktype: map[uint16]string{1:"direct", 2:"opennet", 3:"multihop", 5:"direct"},
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
				Intra: map[uint16]uint8{2:2,3:3,5:0},
			},
			2: {
				Intra: map[uint16]uint8{1:2,3:3,5:1},
			},
			3: {
				Intra: map[uint16]uint8{1:4,2:6,5:3},
			},
			5: {
				Intra: map[uint16]uint8{1:2,2:3,3:4},
			},
		},
		Note:      "asdf",
	}
	passed, info = configcompare(totest,expected)

	return info, passed
}

func compareStaticinfo(totest, expected StaticInfoExtn) (bool, string){
	res := true
	var info string

	if totest.Latency.Egresslatency == expected.Latency.Egresslatency {
		res = res && true
	} else {
		res = false
		info += "Failed to get correct Egresslatency\n"
	}
	if totest.Latency.Intooutlatency == expected.Latency.Intooutlatency {
		res = res && true
	} else {
		res = false
		info += "Failed to get correct Intooutlatency\n"
	}
	for i:= 0; i<len(totest.Latency.Childlatencies); i++{
		temp := false
		for j:= 0; j<len(expected.Latency.Childlatencies); j++{
			if (totest.Latency.Childlatencies[i].Interface == expected.Latency.Childlatencies[j].Interface) && (totest.Latency.Childlatencies[i].Intradelay == expected.Latency.Childlatencies[j].Intradelay){
				temp = true
			}
		}
		res = res && temp
		if !temp{
			info += "Failed to get correct Childlatency for interface " + strconv.Itoa(int(totest.Latency.Childlatencies[i].Interface)) + "\n"
		}
	}
	for i:= 0; i<len(totest.Latency.Peeringlatencies); i++{
		temp := false
		for j:= 0; j<len(expected.Latency.Peeringlatencies); j++{
			if (totest.Latency.Peeringlatencies[i].IntfID == expected.Latency.Peeringlatencies[j].IntfID) && (totest.Latency.Peeringlatencies[i].IntraDelay == expected.Latency.Peeringlatencies[j].IntraDelay) && (totest.Latency.Peeringlatencies[i].Interdelay == expected.Latency.Peeringlatencies[j].Interdelay){
				temp = true
			}
		}
		res = res && temp
		if !temp{
			info += "Failed to get correct Peeringlatencies for interface " + strconv.Itoa(int(totest.Latency.Peeringlatencies[i].IntfID)) + "\n"
		}
	}

	if totest.Bandwidth.EgressBW == expected.Bandwidth.EgressBW {
		res = res && true
	} else {
		res = false
		info += "Failed to get correct EgressBW\n"
	}
	if totest.Bandwidth.IntooutBW == expected.Bandwidth.IntooutBW {
		res = res && true
	} else {
		res = false
		info += "Failed to get correct IntooutBW\n"
	}
	for i:= 0; i<len(totest.Bandwidth.BWPairs); i++{
		temp := false
		for j:= 0; j<len(expected.Bandwidth.BWPairs); j++{
			if (totest.Bandwidth.BWPairs[i].IntfID == expected.Bandwidth.BWPairs[j].IntfID) && (totest.Bandwidth.BWPairs[i].BW == expected.Bandwidth.BWPairs[j].BW){
				temp = true
			}
		}
		res = res && temp
		if !temp{
			info += "Failed to get correct bandwidth for interface " + strconv.Itoa(int(totest.Bandwidth.BWPairs[i].IntfID)) + "\n"
		}
	}

	for i:= 0; i<len(totest.Geo.Locations); i++{
		temp := false
		for j:= 0; j<len(expected.Geo.Locations); j++{
			if (totest.Geo.Locations[i].GPSData.Longitude == expected.Geo.Locations[j].GPSData.Longitude) && (totest.Geo.Locations[i].GPSData.Latitude == expected.Geo.Locations[j].GPSData.Latitude) && (totest.Geo.Locations[i].GPSData.Address == expected.Geo.Locations[j].GPSData.Address){
				temp = true
				for k:=0; k<len(totest.Geo.Locations[i].IntfIDs); k++{
					subtemp := false
					for l:=0; l<len(expected.Geo.Locations[i].IntfIDs); l++{
						if totest.Geo.Locations[i].IntfIDs[k] == expected.Geo.Locations[j].IntfIDs[l] {
							subtemp = true
						}
					}
					if !subtemp{
						info += "Failed to get correct Location assignment for interface " + strconv.Itoa(int(totest.Geo.Locations[i].IntfIDs[k])) + "\n"
					}
					temp = temp && subtemp
				}
			}
		}
		res = res && temp
		if !temp{
			info += "Failed to get correct Location for Location " + totest.Geo.Locations[i].GPSData.Address + "\n"
		}
	}

	if totest.Linktype.EgressLT == expected.Linktype.EgressLT {
		res = res && true
	} else {
		res = false
		info += "Failed to get correct EgressLT\n"
	}
	for i:= 0; i<len(totest.Linktype.Peeringlinks); i++{
		temp := false
		for j:= 0; j<len(expected.Linktype.Peeringlinks); j++{
			if (totest.Linktype.Peeringlinks[i].IntfID == expected.Linktype.Peeringlinks[j].IntfID) && (totest.Linktype.Peeringlinks[i].IntfLT == expected.Linktype.Peeringlinks[j].IntfLT){
				temp = true
			}
		}
		res = res && temp
		if !temp{
			info += "Failed to get correct linktype for interface " + strconv.Itoa(int(totest.Linktype.Peeringlinks[i].IntfID)) + "\n"
		}
	}

	if totest.Hops.Intououthops == expected.Hops.Intououthops {
		res = res && true
	} else {
		res = false
		info += "Failed to get correct Intoouthops\n"
	}
	for i:= 0; i<len(totest.Hops.Hoppairs); i++{
		temp := false
		for j:= 0; j<len(expected.Hops.Hoppairs); j++{
			if (totest.Hops.Hoppairs[i].IntfID == expected.Hops.Hoppairs[j].IntfID) && (totest.Hops.Hoppairs[i].Hops == expected.Hops.Hoppairs[j].Hops){
				temp = true
			}
		}
		res = res && temp
		if !temp{
			info += "Failed to get correct hops for interface " + strconv.Itoa(int(totest.Hops.Hoppairs[i].Hops)) + "\n"
		}
	}

	if totest.Note == expected.Note {
		res = res && true
	} else {
		res = false
		info += "Failed to get correct Note\n"
	}

	return res, info
}


func testGenerateStaticinfo() (bool, string) {
	var testcases []Configdata
	testcases = append(testcases, Configdata{
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
		Bandwidth:  map[uint16]Bwintf{
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
		Linktype: map[uint16]string{1:"direct", 2:"opennet", 3:"multihop", 5:"direct"},
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
				Intra: map[uint16]uint8{2:2,3:3,5:0},
			},
			2: {
				Intra: map[uint16]uint8{1:2,3:3,5:1},
			},
			3: {
				Intra: map[uint16]uint8{1:4,2:6,5:3},
			},
			5: {
				Intra: map[uint16]uint8{1:2,2:3,3:4},
			},
		},
		Note:      "asdf",
	})
	var expected []StaticInfoExtn
	expected = append(expected, StaticInfoExtn{
		Latency:   LatencyInfo{
			Egresslatency: 40,
			Intooutlatency: 70,
			Childlatencies: []Latencychildpair{
				{
					Intradelay: 70,
					Interface: 3,
				},
			},
			Peeringlatencies: []Latencypeeringtriplet{
				{
					Interdelay: 90,
					IntraDelay: 50,
					IntfID: 5,
				},
			},
		},
		Geo:       GeoInfo{
			Locations: []Location{
				{
					GPSData: Coordinates{
						Latitude:  47.2,
						Longitude: 62.2,
						Address:   "geo1",
					},
					IntfIDs: []uint16 {1},
				},
				{
					GPSData: Coordinates{
						Latitude:  79.2,
						Longitude: 45.2,
						Address:   "geo2",
					},
					IntfIDs: []uint16 {2},
				},
				{
					GPSData: Coordinates{
						Latitude:  47.22,
						Longitude: 42.23,
						Address:   "geo3",
					},
					IntfIDs: []uint16 {3},
				},
				{
					GPSData: Coordinates{
						Latitude:  48.2,
						Longitude: 46.2,
						Address:   "geo5",
					},
					IntfIDs: []uint16 {5},
				},
			},
		},
		Linktype:  LinktypeInfo{
			EgressLT: "opennet",
			Peeringlinks: []LTPeeringpair{
				{
					IntfID: 5,
					IntfLT: "direct",
				},
			},
		},
		Bandwidth: BandwidthInfo{
			EgressBW: 5000000,
			IntooutBW: 6555550,
			BWPairs: []BWPair{
				{
					IntfID: 3,
					BW: 6555550,
				},
				{
					IntfID: 5,
					BW: 120,
				},
			},
		},
		Hops:      InternalHopsInfo{
			Hoppairs: []Hoppair{
				 {
				 	IntfID: 3,
				 	Hops: 3,
				 },
				{
					IntfID: 5,
					Hops: 1,
				},
			},
		},
		Note:      "asdf",
	})
	res := true
	var info string
	for i:=0; i< len(testcases); i++{
		data := GenerateStaticinfo(testcases[i], 2, 3)
		testres, testinfo := compareStaticinfo(*data, expected[i])
		res = res && testres
		info += "Testcase " + strconv.Itoa(i) + ":\n"
		if !testres{
			info += testinfo
		}
	}
	return res, info
}
