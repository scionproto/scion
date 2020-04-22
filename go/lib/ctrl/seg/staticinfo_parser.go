package seg

import (
	"fmt"

	"encoding/json"
	"io/ioutil"
	"os"
)


type Latintf struct {
	Inter  uint16     `json:"Inter"`
	Intra  map[uint16]uint16 `json:"Intra"`
}

type Bwintf struct {
	Inter  uint32    `json:"Inter"`
	Intra  map[uint16]uint32 `json:"Intra"`
}

type Geointf struct {
	Longitude      float32 `json:"Longitude"`
	Latitude      float32 `json:"Latitude"`
	Address string  `json:"Address"`
}

type Hopintf struct {
	Intra  map[uint16]uint8 `json:"Intra"`
}

// Configdata is used to parse data from config.json
type Configdata struct {
	Latency  map[uint16]Latintf `json:"Latency"`
	Bandwidth   map[uint16]Bwintf  `json:"Bandwidth"`
	Linktype   map[uint16]string  `json:"Linktype"`
	Geo  map[uint16]Geointf `json:"Geo"`
	Hops map[uint16]Hopintf `json:"Hops"`
	Note    string             `json:"Note"`
}

type Topointf struct {
	LinkTo string `json:"LinkTo"`
}

type BR struct {
	Intfs map[uint16]Topointf `json:"Interfaces"`
}

// Topo is used to parse data from topology.json
type Topo struct {
	BRs map[string]BR `json:"BorderRouters"`
}

// parseconfigdata takes the path of a config.json and the path of a topologyfile, both in the form of a string.
// Parses data from config json into a Configdata struct and uses data from a topologyfile to
// create a map from interfaces to bools indicating whether or not the interface is used in peering.
// Returns the Configdata struct as well as the map from intfIDs to bools.
func parsenconfigdata(datafile string, topologyfile string) (Configdata, map[uint16]bool) {
	jsonFile, err := os.Open(datafile)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	rawfile, _ := ioutil.ReadAll(jsonFile)
	var res Configdata
	json.Unmarshal(rawfile, &res)
	var temp Topo
	peers := make(map[uint16]bool)
	topologyjson, err := os.Open(topologyfile)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	topologyraw,_ := ioutil.ReadAll(topologyjson)
	json.Unmarshal(topologyraw, &temp)
	for _,BR := range temp.BRs{
		for intf, val := range BR.Intfs{
			peers[intf] = (val.LinkTo == "PEER")
		}
	}
	return res, peers
}

// generateStaticinfo the path of a config.json and the path of a topologyfile, both in the form of a string, as well as
// an egress and an ingress interface ID.
// Fills a StaticinfoExtn struct with data extracted from a config.json and a topologyfile.
// Returns a pointer to said StaticInfoExtn struct.
func generateStaticinfo(datafile string, topologyfile string, egIFID uint16, inIFID uint16) *StaticInfoExtn {
	var somedata, peers = parsenconfigdata(datafile, topologyfile)
	var res StaticInfoExtn
	res.Latency.gatherlatency(somedata, peers, egIFID, inIFID)
	res.Bandwidth.gatherbw(somedata, peers, egIFID, inIFID)
	res.Linktype.gatherlinktype(somedata, peers, egIFID)
	res.Geo.gathergeo(somedata)
	res.Note = somedata.Note
	res.Hops.gatherhops(somedata, egIFID, inIFID)
	return &res
}
