package beaconing

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
)

// Parseconfigdata parses data from a config file into a Configdata struct.
func Parsenconfigdata(datafile string) (seg.Configdata, error) {
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
	var Cfgdata seg.Configdata
	json.Unmarshal(rawfile, &Cfgdata)
	return Cfgdata, Myerror
}

// GenerateStaticinfo creates a StaticinfoExtn struct and populates it with data extracted from configdata.
func GenerateStaticinfo(configdata seg.Configdata, peers map[uint16]bool, egifID uint16, inifID uint16) seg.StaticInfoExtn {
	var StaticInfo seg.StaticInfoExtn
	StaticInfo.Latency.Gatherlatency(configdata, peers, egifID, inifID)
	StaticInfo.Bandwidth.Gatherbw(configdata, peers, egifID, inifID)
	StaticInfo.Linktype.Gatherlinktype(configdata, peers, egifID)
	StaticInfo.Geo.Gathergeo(configdata)
	StaticInfo.Note = configdata.Note
	StaticInfo.Hops.Gatherhops(configdata, egifID, inifID)
	return StaticInfo
}
