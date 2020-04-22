package seg

import (
	"fmt"

	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
)

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
	EgIFID uint16             `json:"Egress"`
	InIFID uint16             `json:"Ingress"`
	LI LatencyInfoTest      `json:"ExpLatency"`
	GI GeoInfoTest          `json:"ExpGeo"`
	LT LinktypeInfoTest     `json:"ExpLT"`
	BW BandwidthInfoTest    `json:"ExpBW"`
	IH InternalHopsInfoTest `json:"ExpIH"`
	NI string                 `json:"ExpNI"`
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
	res = res && (test.LI.Intooutlatency == totest.LI.Intooutlatency) && (test.LI.Egresslatency == totest.LI.Egresslatency)
	for _, pair := range totest.LI.Childlatencies{
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

	for _, pair := range totest.LI.Peeringlatencies{
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

	res = res && (test.BW.IntooutBW == totest.BW.IntooutBW) && (test.BW.EgressBW == totest.BW.EgressBW)
	for _, pair := range totest.BW.BWPairs{
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

	res = res && (test.LT.EgressLT == totest.LT.EgressLT)
	for _, pair := range totest.LT.Peeringlinks {
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

	for _, loc := range totest.GI.Locations {
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

	res = res && (test.IH.Intououthops == totest.IH.Intououthops)
	for _, pair := range totest.IH.Hoppairs{
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

	res = res && (test.NI == totest.NI)

	if !(test.NI == totest.NI) {
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
		totest := generateStaticinfo(datafiles[i], topofiles[i], ExpRes.EgIFID, ExpRes.InIFID)
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

