package seg

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/scionproto/scion/go/cs/beaconing"
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

// Parseconfigdata parses data from a config file into a Configdata struct.
func Parsenconfigdata(datafile string) (Configdata, error) {
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



// GenerateStaticinfo creates a StaticinfoExtn struct and populates it with data extracted from configdata.
func GenerateStaticinfo(configdata Configdata, peers map[uint16]bool, egifID uint16, inifID uint16) StaticInfoExtn {
	var res StaticInfoExtn
	res.Latency.gatherlatency(configdata, peers, egifID, inifID)
	res.Bandwidth.gatherbw(configdata, peers, egifID, inifID)
	res.Linktype.gatherlinktype(configdata, peers, egifID)
	res.Geo.gathergeo(configdata)
	res.Note = configdata.Note
	res.Hops.gatherhops(configdata, egifID, inifID)
	return res
}
