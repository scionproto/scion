package seg

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
)

type Latintf struct {
	Inter uint16            `json:"Inter"`
	Intra map[uint16]uint16 `json:"Intra"`
}

type Bwintf struct {
	Inter uint32            `json:"Inter"`
	Intra map[uint16]uint32 `json:"Intra"`
}

type Geointf struct {
	Longitude float32 `json:"Longitude"`
	Latitude  float32 `json:"Latitude"`
	Address   string  `json:"Address"`
}

type Hopintf struct {
	Intra map[uint16]uint8 `json:"Intra"`
}

// Configdata is used to parse data from config.json.
type Configdata struct {
	Latency   map[uint16]Latintf `json:"Latency"`
	Bandwidth map[uint16]Bwintf  `json:"Bandwidth"`
	Linktype  map[uint16]string  `json:"Linktype"`
	Geo       map[uint16]Geointf `json:"Geo"`
	Hops      map[uint16]Hopintf `json:"Hops"`
	Note      string             `json:"Note"`
}

// Parseconfigdata parses data from a config file into a Configdata struct.
func Parsenconfigdata(datafile string) (Configdata, error) {
	var Myerror error
	jsonFile, err := os.Open(datafile)
	if err != nil {
		Myerror = errors.New("Failed to open config data file with error: " + err.Error())
	}
	defer jsonFile.Close()
	rawfile, err2 := ioutil.ReadAll(jsonFile)
	if err2 != nil {
		Myerror = errors.New("Failed to read opened file with error: " + err2.Error())
	}
	var Cfgdata Configdata
	json.Unmarshal(rawfile, &Cfgdata)
	return Cfgdata, Myerror
}

// GenerateStaticinfo creates a StaticinfoExtn struct and populates it with data extracted from configdata.
func GenerateStaticinfo(configdata Configdata, peers map[uint16]bool, egifID uint16, inifID uint16) StaticInfoExtn {
	var StaticInfo StaticInfoExtn
	StaticInfo.Latency.gatherlatency(configdata, peers, egifID, inifID)
	StaticInfo.Bandwidth.gatherbw(configdata, peers, egifID, inifID)
	StaticInfo.Linktype.gatherlinktype(configdata, peers, egifID)
	StaticInfo.Geo.gathergeo(configdata)
	StaticInfo.Note = configdata.Note
	StaticInfo.Hops.gatherhops(configdata, egifID, inifID)
	return StaticInfo
}
