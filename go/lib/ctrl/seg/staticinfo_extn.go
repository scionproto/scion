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


type Latency_Info struct {
	Egresslatency uint16 `capnp: "egresslatency"`
	Intooutlatency uint16 `capnp: "intouutlatency"`
	Childlatencies    []Latencychildpair
	Peeringlatencies     []Latencypeeringtriplet
}

type Latencychildpair struct {
	Intradelay uint16   `capnp:"clusterdelay"`
	Interface  uint16 `capnp:"interfaces"`
}

type Latencypeeringtriplet struct {
	Interdelay uint16 `capnp:"clusterdelay"`
	IntraDelay uint16
	IntfID uint16
}


type Bandwidth_Info struct {
	EgressBW uint32 `capnp:"egressbw"`
	IntooutBW uint32 `capnp: "intooutBW"`
	BWPairs []BWPair
}

type BWPair struct {
	BW  uint32   `capnp:"clusterbw"`
	IntfID uint16 `capnp:"interfaces"`
}


type Geo_Info struct {
	Locations []Location
}

type Location struct {
	GPSData      Coordinates
	IntfIDs []uint16 `capnp:"interfaces"`
}

type Coordinates struct {
	Latitude   float32 `capnp:"gps1"`
	Longitude   float32 `capnp:"gps2"`
	Address string  `capnp:"civadd"`
}


type Linktype_Info struct {
	EgressLT   string `capnp: "egresslt"`
	Peeringlinks  []LTPeeringpair
}

type LTPeeringpair struct {
	IntfID uint16 `capnp:"interface"`
	IntfLT string `capnp:"interlt"`
}


type InternalHops_Info struct {
	Intououthops uint8 `capnp: "intoouthops"`
	Hoppairs []Hoppair
}

type Hoppair struct {
	Hops uint8    `capnp:"clusterhops"`
	IntfID uint16 `capnp:"interfaces"`
}


type StaticInfoExtn struct {
	LI Latency_Info      `capnp:"ei"`
	GI Geo_Info          `capnp:"gi"`
	LT Linktype_Info     `capnp:"lt"`
	BW Bandwidth_Info    `capnp:"bw"`
	IH InternalHops_Info `capnp:"ih"`
	NI string            `capnp:"ni"`
}

//use maps and for key,val := range mymap{}


func (latinf *Latency_Info) gatherlatency(somestruct MI2, peers map[uint16]bool, eintfID uint16, inIFID uint16) {
	var egressLat uint16
	for mainintfid, intfdelay := range somestruct.Lat {
		if mainintfid == eintfID {
			egressLat = intfdelay.Inter
			for subintfid, subdelay := range intfdelay.Intra {
				if (subintfid == inIFID) {
					latinf.Intooutlatency = subdelay
				}
			}
		}
	}
	latinf.Egresslatency = egressLat
	for mainintfid, intfdelay := range somestruct.Lat {
		if !(peers[mainintfid]) {
			for  subintfid, subdelay := range intfdelay.Intra {
				if (mainintfid > subintfid) && (subintfid == eintfID) {
					var asdf Latencychildpair
					asdf.Intradelay = subdelay
					asdf.Interface = mainintfid
					latinf.Childlatencies = append(latinf.Childlatencies, asdf)
				}
			}
		} else {
			for subintfid, subdelay := range intfdelay.Intra {
				if (mainintfid > subintfid) && (subintfid == eintfID) {
					var asdf Latencypeeringtriplet
					asdf.IntfID = mainintfid
					asdf.Interdelay = intfdelay.Inter
					asdf.IntraDelay = subdelay
					latinf.Peeringlatencies = append(latinf.Peeringlatencies, asdf)
				}
			}
		}
	}
}


func (bwinf *Bandwidth_Info) gatherbw(somestruct MI2, peers map[uint16]bool, eintfID uint16, inIFID uint16) {
	var egressBW uint32
	for mainintfid, intfbw := range somestruct.BW {
		if mainintfid == eintfID {
			egressBW = intfbw.Inter
			for subintfid, subintfbw := range intfbw.Intra {
				if subintfid == inIFID {
					bwinf.IntooutBW = subintfbw
				}
			}
		}
	}
	bwinf.EgressBW = egressBW
	for mainintfid, intfbw := range somestruct.BW {
		var actualbw uint32
		for subintfid, subintfbw := range intfbw.Intra {
			if (subintfid == eintfID) && (mainintfid > subintfid) {
				if peers[mainintfid] {
					actualbw = uint32(math.Min(float64(subintfbw), float64(intfbw.Inter)))
				} else {
					actualbw = subintfbw
				}
				var asdf BWPair
				asdf.BW = actualbw
				asdf.IntfID = mainintfid
				bwinf.BWPairs = append(bwinf.BWPairs, asdf)
			}
		}
	}
}


func (ltinf *Linktype_Info) gatherlinktype(somestruct MI2, peers map[uint16]bool, eintfID uint16) {
	for intfid, intfLT := range somestruct.LT {
		if intfid == eintfID {
			ltinf.EgressLT = intfLT
		}
		if (peers[intfid]) {
			var asdf LTPeeringpair
			asdf.IntfLT = intfLT
			asdf.IntfID = intfid
			ltinf.Peeringlinks = append(ltinf.Peeringlinks, asdf)
		}
	}
}


func (nhinf *InternalHops_Info) gatherhops(somestruct MI2, eintfID uint16, inIFID uint16){
	for mainintfid, intfhops := range somestruct.Hops {
		for subintfid, subintfhops := range intfhops.Intra {
			if (subintfid == eintfID) {
				if mainintfid == inIFID {
					nhinf.Intououthops = subintfhops
				}
				if (mainintfid > subintfid) {
					var asdf Hoppair
					asdf.Hops = subintfhops
					asdf.IntfID = mainintfid
					nhinf.Hoppairs = append(nhinf.Hoppairs, asdf)
				}
			}
		}
	}
}


func (geoinf *Geo_Info) gathergeo(somestruct MI2) {
	for intfid, loc := range somestruct.Geo {
		var assigned = false
		for k := 0; k < len(geoinf.Locations); k++ {
			if (loc.Longitude >= geoinf.Locations[k].GPSData.Longitude-0.0005) && (loc.Longitude < geoinf.Locations[k].GPSData.Longitude+0.0005) && ((loc.Latitude >= geoinf.Locations[k].GPSData.Latitude-0.0005) && (loc.Latitude < geoinf.Locations[k].GPSData.Latitude+0.0005)) && (!assigned) {
				geoinf.Locations[k].IntfIDs = append(geoinf.Locations[k].IntfIDs, intfid)
				assigned = true
			}
		}
		if !assigned {
			var asdf Location
			asdf.GPSData.Longitude = loc.Longitude
			asdf.GPSData.Latitude = loc.Latitude
			asdf.GPSData.Address = loc.Address
			asdf.IntfIDs = append(asdf.IntfIDs, intfid)
			geoinf.Locations = append(geoinf.Locations, asdf)
			assigned = true
		}
	}
}
