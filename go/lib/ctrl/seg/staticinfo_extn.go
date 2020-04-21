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
	Egresslatency uint16 `capnp: "egressLatency"`
	Intooutlatency uint16 `capnp: "ingressToEgressLatency"`
	Childlatencies    []Latencychildpair `capnp: "childLatencies"`
	Peeringlatencies     []Latencypeeringtriplet `capnp: "peeringLatencies"`
}

type Latencychildpair struct {
	Intradelay uint16   `capnp:"intraDelay"`
	Interface  uint16 `capnp:"interface"`
}

type Latencypeeringtriplet struct {
	Interdelay uint16 `capnp:"interDelay"`
	IntraDelay uint16 `capnp: "intraDelay"`
	IntfID uint16 `capnp: "interface"`
}


type Bandwidth_Info struct {
	EgressBW uint32 `capnp:"egressBW"`
	IntooutBW uint32 `capnp: "ingressToEgressBW"`
	BWPairs []BWPair `capnp: "bandwidthPairs"`
}

type BWPair struct {
	BW  uint32   `capnp:"BW"`
	IntfID uint16 `capnp:"interface"`
}


type Geo_Info struct {
	Locations []Location `capnp: "locations"`
}

type Location struct {
	GPSData      Coordinates `capnp: "gpsData"`
	IntfIDs []uint16 `capnp:"interfaces"`
}

type Coordinates struct {
	Latitude   float32 `capnp:"latitude"`
	Longitude   float32 `capnp:"longitude"`
	Address string  `capnp:"address"`
}


type Linktype_Info struct {
	EgressLT   string `capnp: "egressLinkType"`
	Peeringlinks  []LTPeeringpair `capnp: "peeringLinks"`
}

type LTPeeringpair struct {
	IntfID uint16 `capnp:"interface"`
	IntfLT string `capnp:"peeringLinkType"`
}


type InternalHops_Info struct {
	Intououthops uint8 `capnp: "inToOutHops"`
	Hoppairs []Hoppair `capnp: "hopPairs"`
}

type Hoppair struct {
	Hops uint8    `capnp:"Hops"`
	IntfID uint16 `capnp:"interface"`
}


type StaticInfoExtn struct {
	LI Latency_Info      `capnp:"latency"`
	GI Geo_Info          `capnp:"geo"`
	LT Linktype_Info     `capnp:"linktype"`
	BW Bandwidth_Info    `capnp:"bandwidth"`
	IH InternalHops_Info `capnp:"internalHops"`
	NI string            `capnp:"note"`
}

// Takes an intermediate struct only used to parse data from a config.json file, a map of interface IDs to
// booleans indicating whether the interface in question is used for peering, and egress interface ID and an
// ingress interface ID.
// Extracts latency values from that struct and inserts them into the latency portion of a StaticInfoExtn struct.
func (latinf *Latency_Info) gatherlatency(somestruct Configdata, peers map[uint16]bool, egIFID uint16, inIFID uint16) {
	var egressLat uint16
	for mainintfid, intfdelay := range somestruct.Lat {
		if mainintfid == egIFID {
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
				if (mainintfid > subintfid) && (subintfid == egIFID) {
					var asdf Latencychildpair
					asdf.Intradelay = subdelay
					asdf.Interface = mainintfid
					latinf.Childlatencies = append(latinf.Childlatencies, asdf)
				}
			}
		} else {
			for subintfid, subdelay := range intfdelay.Intra {
				if (mainintfid > subintfid) && (subintfid == egIFID) {
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

// Takes an intermediate struct only used to parse data from a config.json file, a map of interface IDs to
// booleans indicating whether the interface in question is used for peering, and egress interface ID and an
// ingress interface ID.
// Extracts bandwidth values from that struct and inserts them into the bandwidth portion of a StaticInfoExtn struct.
func (bwinf *Bandwidth_Info) gatherbw(somestruct Configdata, peers map[uint16]bool, egIFID uint16, inIFID uint16) {
	var egressBW uint32
	for mainintfid, intfbw := range somestruct.BW {
		if mainintfid == egIFID {
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
			if (subintfid == egIFID) && (mainintfid > subintfid) {
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

// Takes an intermediate struct only used to parse data from a config.json file, a map of interface IDs to
// booleans indicating whether the interface in question is used for peering, and egress interface ID.
// Extracts linktype values from that struct and inserts them into the linktype portion of a StaticInfoExtn struct.
func (ltinf *Linktype_Info) gatherlinktype(somestruct Configdata, peers map[uint16]bool, egIFID uint16) {
	for intfid, intfLT := range somestruct.LT {
		if intfid == egIFID {
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


func (nhinf *InternalHops_Info) gatherhops(somestruct Configdata, egIFID uint16, inIFID uint16){
	for mainintfid, intfhops := range somestruct.Hops {
		for subintfid, subintfhops := range intfhops.Intra {
			if (subintfid == egIFID) {
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

// Takes an intermediate struct only used to parse data from a config.json file.
// Extracts geo values from that struct and inserts them into the geo portion of a StaticInfoExtn struct.
func (geoinf *Geo_Info) gathergeo(somestruct Configdata) {
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
