package combinator

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/proto"
	"math"
)


type ASnote struct {
	addr.IA
	Note string
}

type ASgeo struct {
	IA addr.IA
	locations []geoloc
}

type geoloc struct {
	Latitude float32
	Longitude float32
	CivAddr string
}

type ASdelay struct {
	IA addr.IA
	Intradelay uint16
	Interdelay uint16
	Peerdelay uint16
}

type AShops struct {
	IA addr.IA
	Hops uint8
}

type ASlink struct {
	IA addr.IA
	Interlink string
	Peerlink string
}

type ASbw struct {
	IA addr.IA
	Intrabw uint32
	Interbw uint32
	Peerbw uint32
}

type Pathmetadata struct {
	UpASes []addr.IA
	CoreASes []addr.IA
	DownASes []addr.IA
	SingleDelays map[addr.IA]ASdelay
	Singlebw map[addr.IA]ASbw
	SingleHops map[addr.IA]AShops
	Internalhops map[addr.IA]uint8
	Geo map[addr.IA]ASgeo
	Links map[addr.IA]ASlink
	Notes map[addr.IA]ASnote
	Upover bool
	Downover bool
	DownoverIFID common.IFIDType
	UpOverentry *seg.ASEntry
	Peerover bool
	PeeroverIFID common.IFIDType
}

// Condensed form of metadata retaining only most important values.
type Densemetadata struct {
	ASes []addr.IA
	totaldelay uint16
	totalhops uint8
	minofmaxbws uint32
	links map[addr.IA]ASlink
	locations map[addr.IA]ASgeo
	Notes map[addr.IA]string
}


func (data *Pathmetadata) Condensemetadata() *Densemetadata{
	ret := &Densemetadata{
		totaldelay: 0,
		totalhops: 0,
		minofmaxbws: math.MaxUint32,
	}

	for _,val := range data.Singlebw{
		var asmaxbw uint32
		asmaxbw = math.MaxUint32
		if(val.Intrabw>0){
			asmaxbw = uint32(math.Min(float64(val.Intrabw),float64(asmaxbw)))
		}
		if(val.Interbw>0){
			asmaxbw = uint32(math.Min(float64(val.Interbw),float64(asmaxbw)))
		}
		if(val.Peerbw>0){
			asmaxbw = uint32(math.Min(float64(val.Peerbw),float64(asmaxbw)))
		}
		if(asmaxbw<(math.MaxUint32)){
			ret.minofmaxbws = uint32(math.Min(float64(ret.minofmaxbws),float64(asmaxbw)))
		}
	}

	if !(ret.minofmaxbws<math.MaxUint32){
		ret.minofmaxbws = 0
	}

	for _,val := range data.SingleDelays{
		ret.totaldelay += val.Interdelay + val.Intradelay + val.Peerdelay
	}

	for  _,val := range data.SingleHops{
		ret.totalhops += val.Hops
	}
	for IA,note := range data.Notes{
		ret.Notes[IA] = note.Note
	}
	for IA,loc := range data.Geo{
		ret.locations[IA] = loc
	}
	for IA,link := range data.Links{
		ret.links[IA] =  link
	}

	for i:=0;i<len(data.UpASes);i++  {
		ret.ASes = append(ret.ASes, data.UpASes[i])
	}
	for i:=len(data.CoreASes)-1;i>=0;i--  {
		ret.ASes = append(ret.ASes, data.CoreASes[i])
	}
	for i:=len(data.DownASes)-1;i>=0;i--  {
		ret.ASes = append(ret.ASes, data.DownASes[i])
	}

	return ret
}

func (solution *PathSolution) Assemblepcbmetadata() *Pathmetadata{
	res := &Pathmetadata{
		Upover: false,
		Downover: false,
		Peerover: false,
	}
	/*
		Iterate over solutionEdges in solution, start in last ASEntry, go until entry with index "shortcut"
		While not shortcut, simply assemble metadata normally by using intoout metrics in the ASEntry's staticinfoextn.
		If index == shortcut, check if "normal" shortcut or peering shortcut (if peer != 0) and treat accordingly.
		Also make sure to treat the first entry in the up and down segs (i.e. first and last ASes on the path)
		specially, since there is no metadata to collect on those ASes.
	*/
	for _, solEdge := range solution.edges{
		asEntries := solEdge.segment.ASEntries
		var iscoreseg proto.PathSegType
		iscoreseg = proto.PathSegType_core
		for asEntryIdx := len(asEntries) - 1; asEntryIdx >= solEdge.edge.Shortcut; asEntryIdx-- {
			if (solEdge.segment.Type == iscoreseg){
				res.CoreASes = append(res.CoreASes, asEntries[asEntryIdx].IA())
			}
			if solEdge.segment.IsDownSeg(){
				res.DownASes = append(res.DownASes, asEntries[asEntryIdx].IA())
			}
			if (!(solEdge.segment.Type == iscoreseg)) && (!(solEdge.segment.IsDownSeg())){
				res.UpASes = append(res.UpASes, asEntries[asEntryIdx].IA())
			}
			if (asEntryIdx>solEdge.edge.Shortcut) {
				asEntry := asEntries[asEntryIdx]
				hopEntry := asEntry.HopEntries[0]
				HF,_ := hopEntry.HopField()
				inIFID := HF.ConsIngress
				var SI *seg.StaticInfoExtn
				SI = asEntry.Exts.StaticInfo
				var currdelay ASdelay
				var currhops AShops
				var currlinks ASlink
				var currnotes ASnote
				var currgeo ASgeo
				var currbw ASbw

				// If we're in the middle of a segment, simply take data from staticinfoextn in
				// the corresponding ASEntry and put it into res
				if !(asEntryIdx==(len(asEntries)-1)){
					IA := asEntry.IA()
					currdelay.Intradelay = SI.Latency.Intooutlatency
					currdelay.IA = IA
					currdelay.Interdelay = SI.Latency.Egresslatency
					currdelay.Peerdelay = 0
					currlinks.IA = IA
					currlinks.Interlink = SI.Linktype.EgressLT
					currlinks.Peerlink = ""
					currbw.IA = IA
					currbw.Interbw = SI.Bandwidth.EgressBW
					currbw.Intrabw = SI.Bandwidth.IntooutBW
					currbw.Peerbw = 0
					currhops.IA = IA
					currhops.Hops = SI.Hops.Intououthops
					currgeo.locations = gathergeo(SI, asEntry)
					currnotes.Note = SI.Note
					res.SingleDelays[IA] = currdelay
					res.SingleHops[IA] = currhops
					res.Singlebw[IA] = currbw
					res.Links[IA] = currlinks
					res.Geo[IA] = currgeo
					res.Notes[IA] = currnotes
				}
				// If we're in the last AS of a coresegment (i.e. the first inspected entry),
				// save the entry as overentry and set xover flag.
				if (solEdge.segment.Type == iscoreseg) && (asEntryIdx==(len(asEntries)-1)){

					res.Downover = true
					res.DownoverIFID = inIFID
				}
				// If we're in the first AS in an up or last AS in a down segment (i.e. first inspected entry),
				// set all entries to 0, except for geo.
				if (!(solEdge.segment.Type == iscoreseg)) && (asEntryIdx==(len(asEntries)-1)){
					IA := asEntry.IA()
					currdelay.Intradelay = 0
					currdelay.Interdelay = 0
					currdelay.Peerdelay = 0
					currdelay.IA = asEntry.IA()
					currlinks.IA = IA
					currlinks.Interlink = ""
					currlinks.Peerlink = ""
					currbw.IA = IA
					currbw.Interbw = 0
					currbw.Intrabw = 0
					currbw.Peerbw = 0
					currhops.IA = IA
					currhops.Hops = 0
					currgeo.locations = gathergeo(SI, asEntry)
					currnotes.Note = SI.Note
					res.SingleDelays[IA] = currdelay
					res.SingleHops[IA] = currhops
					res.Singlebw[IA] = currbw
					res.Links[IA] = currlinks
					res.Geo[IA] = currgeo
					res.Notes[IA] = currnotes
				}
			} else {
				asEntry := asEntries[asEntryIdx]
				hopEntry := asEntry.HopEntries[0]
				var SI *seg.StaticInfoExtn
				SI = asEntry.Exts.StaticInfo
				if (solEdge.edge.Peer != 0) {
					peerEntry := asEntry.HopEntries[solEdge.edge.Peer]
					PE, _ := peerEntry.HopField()
					inIFID := PE.ConsIngress
					// Treat peering link crossover case by simply adding everything as we would in the case of
					// an AS somewhere in the middle of a segment, with the exception that the peering interface is
					// used as the ingress interface. Set peerover flag.
					var currdelay ASdelay
					var currhops AShops
					var currlinks ASlink
					var currnotes ASnote
					var currgeo ASgeo
					var currbw ASbw
					IA := asEntry.IA()
					// If res.Peerover is set, include the data about the peering connection, else ignore it
					// (so it isn't included twice)
					if res.Peerover {
						currdelay.Intradelay, currdelay.Peerdelay, currdelay.IA = gatherpeeringlatencydata(SI, asEntry, res.PeeroverIFID)
						currlinks.Peerlink = gatherpeeroverlink(SI, asEntry, res.PeeroverIFID)
						res.Peerover = false
					} else {
						currdelay.Intradelay, currdelay.IA = gatherxoverlatency(SI, asEntry, inIFID)
						res.Peerover = true
					}
					currdelay.Interdelay = SI.Latency.Egresslatency
					res.PeeroverIFID = peerEntry.RemoteInIF
					currlinks.IA = IA
					currlinks.Interlink = SI.Linktype.EgressLT
					currbw.IA = IA
					currbw.Interbw = SI.Bandwidth.EgressBW
					currbw.Intrabw = gatherxoverbw(SI, asEntry, inIFID)
					currhops.IA = IA
					currhops.Hops = gatherxoverhops(SI, asEntry, inIFID)
					currgeo.locations = gathergeo(SI, asEntry)
					currnotes.Note = SI.Note
					res.SingleDelays[IA] = currdelay
					res.SingleHops[IA] = currhops
					res.Singlebw[IA] = currbw
					res.Links[IA] = currlinks
					res.Geo[IA] = currgeo
					res.Notes[IA] = currnotes
					continue
				} else {
					// If we're in the AS where we cross over from an up to a core or down segment
					// (i.e. res.Upover is set), fill pathmetadata using res.UpOverentry
					if res.Upover {
						var oldSI *seg.StaticInfoExtn
						var currdelay ASdelay
						var currhops AShops
						var currlinks ASlink
						var currnotes ASnote
						var currgeo ASgeo
						var currbw ASbw
						oldSI = res.UpOverentry.Exts.StaticInfo
						IA := asEntry.IA()
						HF,_ := hopEntry.HopField()
						egIFID := HF.ConsEgress
						currdelay.Intradelay, currdelay.IA = gatherxoverlatency(oldSI, res.UpOverentry, egIFID)
						currdelay.Interdelay = SI.Latency.Egresslatency
						currdelay.Peerdelay = oldSI.Latency.Egresslatency
						// we abuse peerdelay (as well as peerbw and peerlink) here for something that
						// isn't technically a peering  link but it doesn't really matter
						currlinks.IA = IA
						currlinks.Interlink = SI.Linktype.EgressLT
						currlinks.Peerlink = oldSI.Linktype.EgressLT
						currbw.IA = IA
						currbw.Interbw = SI.Bandwidth.EgressBW
						currbw.Intrabw = gatherxoverbw(oldSI, res.UpOverentry, egIFID)
						currbw.Peerbw = oldSI.Bandwidth.EgressBW
						currhops.IA = IA
						currhops.Hops = gatherxoverhops(oldSI, res.UpOverentry, egIFID)
						currgeo.locations = gathergeo(oldSI, res.UpOverentry)
						currnotes.Note = oldSI.Note
						res.SingleDelays[IA] = currdelay
						res.SingleHops[IA] = currhops
						res.Singlebw[IA] = currbw
						res.Links[IA] = currlinks
						res.Geo[IA] = currgeo
						res.Notes[IA] = currnotes
						res.Upover = false
					}
					// If we're in the AS where we cross over from a core to a down segment
					// (i.e. res.Downover is set), fill pathmetadata using current ASEntry with
					// res.DownoverIFID as ingress interface
					if res.Downover{
						var currdelay ASdelay
						var currhops AShops
						var currlinks ASlink
						var currnotes ASnote
						var currgeo ASgeo
						var currbw ASbw
						IA := asEntry.IA()
						currdelay.Intradelay, currdelay.IA = gatherxoverlatency(SI, asEntry, res.DownoverIFID)
						currdelay.Interdelay = SI.Latency.Egresslatency
						currdelay.Peerdelay = 0
						currlinks.IA = IA
						currlinks.Interlink = SI.Linktype.EgressLT
						currlinks.Peerlink = ""
						currbw.IA = IA
						currbw.Interbw = SI.Bandwidth.EgressBW
						currbw.Intrabw = gatherxoverbw(SI, asEntry, res.DownoverIFID)
						currbw.Peerbw = 0
						currhops.IA = IA
						currhops.Hops = gatherxoverhops(SI, asEntry, res.DownoverIFID)
						currgeo.locations = gathergeo(SI, asEntry)
						currnotes.Note = SI.Note
						res.SingleDelays[IA] = currdelay
						res.SingleHops[IA] = currhops
						res.Singlebw[IA] = currbw
						res.Links[IA] = currlinks
						res.Geo[IA] = currgeo
						res.Notes[IA] = currnotes
						res.Downover = false
					}
					if !(solEdge.segment.Type == iscoreseg){
						res.Upover = true
						res.UpOverentry = asEntry
					}
				}
			}
		}
	}
	return res
}


func gatherxoverlatency(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) (uint16, addr.IA){
	var ret1 uint16
	var ret2 addr.IA
	for i:=0;i< len(SI.Latency.Childlatencies);i++{
		if (common.IFIDType(SI.Latency.Childlatencies[i].Interface)==inIFID){
			ret1 = SI.Latency.Childlatencies[i].Intradelay
			ret2 = asEntry.IA()
		}
	}
	return ret1, ret2
}


func gatherpeeringlatencydata(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) (uint16, uint16, addr.IA){
	var intradelay, peeringdelay uint16
	var ret3 addr.IA
	for i:=0;i< len(SI.Latency.Peeringlatencies);i++{
		if (common.IFIDType(SI.Latency.Peeringlatencies[i].IntfID)==inIFID){
			intradelay = SI.Latency.Peeringlatencies[i].IntraDelay
			peeringdelay = SI.Latency.Peeringlatencies[i].Interdelay
			ret3 = asEntry.IA()
		}
	}
	return intradelay, peeringdelay, ret3
}


func gatherpeeroverlink(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) (string){
	var interLT string
	for i:=0;i< len(SI.Linktype.Peeringlinks);i++{
		if (common.IFIDType(SI.Linktype.Peeringlinks[i].IntfID)==inIFID){
			interLT = SI.Linktype.Peeringlinks[i].IntfLT
		}
	}
	return interLT
}


func gatherxoverbw(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) uint32{
	var ret1 uint32
	for i:=0;i< len(SI.Bandwidth.BWPairs);i++ {
		if (common.IFIDType(SI.Bandwidth.BWPairs[i].IntfID) == inIFID) {
			ret1 = SI.Bandwidth.BWPairs[i].BW
		}
	}
	return ret1
}

func gatherxoverhops(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) uint8 {
	var ret1 uint8
	for i := 0; i < len(SI.Hops.Hoppairs); i++ {
		if (common.IFIDType(SI.Hops.Hoppairs[i].IntfID) == inIFID) {
			ret1 = SI.Hops.Hoppairs[i].Hops
		}
	}
	return ret1
}


func gathergeo(SI *seg.StaticInfoExtn, entry *seg.ASEntry) ([]geoloc){
	var ret []geoloc
	for _, geocluster := range SI.Geo.Locations{
		var tempcluster geoloc
		tempcluster.Latitude = geocluster.GPSData.Latitude
		tempcluster.Longitude = geocluster.GPSData.Longitude
		tempcluster.CivAddr = geocluster.GPSData.Address
		ret = append(ret, tempcluster)
	}
	return ret
}
