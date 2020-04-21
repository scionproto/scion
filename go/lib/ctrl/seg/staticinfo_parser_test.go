package seg

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/proto"

  "encoding/json"
	"io/ioutil"
	"os"
	"math"
	"strconv"
)


type Topointf struct {
	LinkTo string `json:"LinkTo"`
}

type BR struct {
	Intfs map[uint16]Topointf `json:"Interfaces"`
}

type Topo struct {
	BRs map[string]BR `json:"BorderRouters"`
}


type Latency_Info_Test struct {
	Egresslatency uint16 `json:"ExpEgress"`
	Intooutlatency uint16 `json:"ExpIO"`
	Childlatencies    []Latencychildpair_test `json:"ExpCL"`
	Peeringlatencies     []Latencypeeringtriplet_test `json:"ExpPT"`
}

type Latencychildpair_test struct {
	Intradelay uint16   `json:"ExpIntra"`
	Interface  uint16 `json:"ExpIntf"`
}

type Latencypeeringtriplet_test struct {
	Interdelay uint16 `json:"ExpInter"`
	IntraDelay uint16 `json:"ExpIntra"`
	IntfID uint16 `json:"ExpIntf"`
}

type Bandwidth_Info_Test struct {
	EgressBW uint32 `json:"ExpEgress"`
	IntooutBW uint32 `json:"ExpIO"`
	BWPairs []BWPair_test `json:"ExpBWP"`
}

type BWPair_test struct {
	BW  uint32   `json:"ExpBWV"`
	IntfID uint16 `json:"ExpIntf"`
}

type Geo_Info_Test struct {
	Locations []Location_test `json:"ExpLocs"`
}

type Location_test struct {
	GPSData      Coordinates_test `json:"ExpGPS"`
	IntfIDs []uint16 `json:"ExpIntfs"`
}

type Coordinates_test struct {
	Latitude   float32 `json:"ExpLatitude"`
	Longitude   float32 `json:"ExpLongitude"`
	Address string  `json:"ExpAddr"`
}

type Linktype_Info_Test struct {
	EgressLT   string `json:"ExpEgress"`
	Peeringlinks  []LTPeeringpair_test `json:"ExpPL"`
}

type LTPeeringpair_test struct {
	IntfID uint16 `json:"ExpIntf"`
	IntfLT string `json:"ExpLT"`
}

type InternalHops_Info_Test struct {
	Intououthops uint8 `json:"ExpIO"`
	Hoppairs []Hoppair_test `json:"ExpHP"`
}

type Hoppair_test struct {
	Hops uint8    `json:"ExpHops"`
	IntfID uint16 `json:"ExpIntf"`
}

type Test struct {
	EgIFID uint16             `json:"Egress"`
	InIFID uint16             `json:"Ingress"`
	LI Latency_Info_Test      `json:"ExpLatency"`
	GI Geo_Info_Test          `json:"ExpGeo"`
	LT Linktype_Info_Test     `json:"ExpLT"`
	BW Bandwidth_Info_Test    `json:"ExpBW"`
	IH InternalHops_Info_Test `json:"ExpIH"`
	NI string                 `json:"ExpNI"`
}

type Testdata struct {
	Tests []Test `json:"Tests"`
}

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
		//fmt.Println(subtempres)
		if !subtempres {
			retstr += ("Latency, IntfID: " + strconv.Itoa(int(pair.Interface)) + "\n")
		}
		tempres = tempres && subtempres
		subtempres = false
	}
	res = res && tempres
	//fmt.Println(res)
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
	//fmt.Println(res)

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
	//fmt.Println(res)

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
	//fmt.Println(res)

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
	//fmt.Println(res)

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
	//fmt.Println(res)

	res = res && (test.NI == totest.NI)

	if !(test.NI == totest.NI) {
		retstr += ("Note\n")
	}


	return res, retstr
}


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
	//fmt.Print("Opened file: ", somefile, "\n")
	rawfile, _ := ioutil.ReadAll(jsonFile)
	//fmt.Print("Printing rawfile: ", rawfile, "\nRawfile OVER\n")
	var TD Testdata
	json.Unmarshal(rawfile, &TD)
	if (len(TD.Tests)!= len(datafiles)){
		return "Error: Number of tests must match length of input arrays", false
	}
	noerror := true
	var errmsg string
	for i,_ := range datafiles{
		ExpRes := TD.Tests[i]
		totest := parsenew(datafiles[i], topofiles[i], ExpRes.EgIFID, ExpRes.InIFID)
		testpassed, specifics := dochecks(ExpRes, totest)
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


func test() (string, bool){

	var datafiles []string
	var topofiles []string
	datafiles = append(datafiles, "testconfigfile.json")
	topofiles = append(topofiles, "topology.json")

	res1, res2 := subtest(datafiles, topofiles, "expected.json")
	return res1, res2
}

