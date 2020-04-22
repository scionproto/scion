package seg

import (
	"encoding/json"
	"errors"
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
func parsenconfigdata(datafile string) (Configdata, error) {
	var myerror error
	jsonFile, err := os.Open(datafile)
	if err != nil {
		myerror = errors.New("Failed to open config data file with error: " + err.Error())
	}
	defer jsonFile.Close()
	rawfile, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		myerror = errors.New("Failed to read opened file with error: " + err.Error())
	}
	var res Configdata
	json.Unmarshal(rawfile, &res)
	return res, myerror
}


// generateStaticinfo takes as input some Configdata as well as
// an egress and an ingress interface ID.
// Fills a StaticinfoExtn struct with data extracted from a config.json and a topologyfile.
// Returns a pointer to said StaticInfoExtn struct.
func generateStaticinfo(configdata Configdata, egIFID uint16, inIFID uint16) *StaticInfoExtn {
	var res StaticInfoExtn
	res.Latency.gatherlatency(configdata, egIFID, inIFID)
	res.Bandwidth.gatherbw(configdata, egIFID, inIFID)
	res.Linktype.gatherlinktype(configdata, egIFID)
	res.Geo.gathergeo(configdata)
	res.Note = configdata.Note
	res.Hops.gatherhops(configdata, egIFID, inIFID)
	return &res
}
