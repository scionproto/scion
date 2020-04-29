package beaconing

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"math"
	"os"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
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

// gatherlatency extracts latency values from a Configdata struct and
// inserts them into the LatencyInfo portion of a StaticInfoExtn struct.
func (cfgdata Configdata) Gatherlatency(peers map[uint16]bool, egifID uint16, inifID uint16) seg.LatencyInfo {
	var latinf seg.LatencyInfo
	latinf.Egresslatency = cfgdata.Latency[egifID].Inter
	latinf.Intooutlatency = cfgdata.Latency[egifID].Intra[inifID]
	for subintfid, intfdelay := range cfgdata.Latency[egifID].Intra {
		if !(peers[subintfid]) {
			if subintfid > egifID {
				var latpair seg.Latencychildpair
				latpair.Intradelay = intfdelay
				latpair.Interface = subintfid
				latinf.Childlatencies = append(latinf.Childlatencies, latpair)
			}
		} else {
			var lattriple seg.Latencypeeringtriplet
			lattriple.IntfID = subintfid
			lattriple.Interdelay = cfgdata.Latency[subintfid].Inter
			lattriple.IntraDelay = intfdelay
			latinf.Peeringlatencies = append(latinf.Peeringlatencies, lattriple)
		}
	}
	return latinf
}

// gatherbw extracts bandwidth values from a Configdata struct and
// inserts them into the BandwidthInfo portion of a StaticInfoExtn struct.
func (cfgdata Configdata) Gatherbw(peers map[uint16]bool, egifID uint16, inifID uint16) seg.BandwidthInfo {
	var bwinf seg.BandwidthInfo
	bwinf.EgressBW = cfgdata.Bandwidth[egifID].Inter
	bwinf.IntooutBW = cfgdata.Bandwidth[egifID].Intra[inifID]
	for subintfid, intfbw := range cfgdata.Bandwidth[egifID].Intra {
		var minbw uint32
		if subintfid > egifID {
			if peers[subintfid] {
				minbw = uint32(math.Min(float64(intfbw), float64(cfgdata.Bandwidth[subintfid].Inter)))
			} else {
				minbw = intfbw
			}
			var bwpair seg.BWPair
			bwpair.BW = minbw
			bwpair.IntfID = subintfid
			bwinf.BWPairs = append(bwinf.BWPairs, bwpair)
		}
	}
	return bwinf
}

// gatherlinktype extracts linktype values from a Configdata struct and
// inserts them into the LinktypeInfo portion of a StaticInfoExtn struct.
func (cfgdata Configdata) Gatherlinktype(peers map[uint16]bool, egifID uint16) seg.LinktypeInfo {
	var ltinf seg.LinktypeInfo
	ltinf.EgressLT = cfgdata.Linktype[egifID]
	for intfid, intfLT := range cfgdata.Linktype {
		if peers[intfid] {
			var ltpair seg.LTPeeringpair
			ltpair.IntfLT = intfLT
			ltpair.IntfID = intfid
			ltinf.Peeringlinks = append(ltinf.Peeringlinks, ltpair)
		}
	}
	return ltinf
}

// gatherhops extracts hop values from a Configdata struct and
// inserts them into the InternalHopsinfo portion of a StaticInfoExtn struct.
func (cfgdata Configdata) Gatherhops(egifID uint16, inifID uint16) seg.InternalHopsInfo {
	var nhinf seg.InternalHopsInfo
	nhinf.Intououthops = cfgdata.Hops[egifID].Intra[inifID]
	for subintfid, hops := range cfgdata.Hops[egifID].Intra {
		if subintfid > egifID {
			var hoppair seg.Hoppair
			hoppair.Hops = hops
			hoppair.IntfID = subintfid
			nhinf.Hoppairs = append(nhinf.Hoppairs, hoppair)
		}
	}
	return nhinf
}

// gathergeo extracts geo values from a Configdata struct and
// inserts them into the GeoInfo portion of a StaticInfoExtn struct.
func (cfgdata Configdata) Gathergeo() seg.GeoInfo {
	var geoinf seg.GeoInfo
	for intfid, loc := range cfgdata.Geo {
		var assigned = false
		for k := 0; k < len(geoinf.Locations); k++ {
			if (loc.Longitude == geoinf.Locations[k].GPSData.Longitude) && (loc.Latitude == geoinf.Locations[k].GPSData.Latitude) && (loc.Address == geoinf.Locations[k].GPSData.Address) && (!assigned) {
				geoinf.Locations[k].IntfIDs = append(geoinf.Locations[k].IntfIDs, intfid)
				assigned = true
			}
		}
		if !assigned {
			var locaction seg.Location
			locaction.GPSData.Longitude = loc.Longitude
			locaction.GPSData.Latitude = loc.Latitude
			locaction.GPSData.Address = loc.Address
			locaction.IntfIDs = append(locaction.IntfIDs, intfid)
			geoinf.Locations = append(geoinf.Locations, locaction)
			assigned = true
		}
	}
	return geoinf
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
func GenerateStaticinfo(configdata Configdata, peers map[uint16]bool, egifID uint16, inifID uint16) seg.StaticInfoExtn {
	var StaticInfo seg.StaticInfoExtn
	StaticInfo.Latency = configdata.Gatherlatency(peers, egifID, inifID)
	StaticInfo.Bandwidth = configdata.Gatherbw(peers, egifID, inifID)
	StaticInfo.Linktype = configdata.Gatherlinktype(peers, egifID)
	StaticInfo.Geo = configdata.Gathergeo()
	StaticInfo.Note = configdata.Note
	StaticInfo.Hops = configdata.Gatherhops(egifID, inifID)
	return StaticInfo
}
