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
	SingleDelays map[addr.IA]ASdelay
	Singlebw map[addr.IA]ASbw
	SingleHops map[addr.IA]AShops
	Internalhops map[addr.IA]uint8
	Geo map[addr.IA]ASgeo
	Links map[addr.IA]ASlink
	Notes map[addr.IA]ASnote
	Xover bool
	Overentry *seg.ASEntry
	Peerover bool
	PeeroverIFID common.IFIDType
}


/*
TODO: 4)IMPLEMENT AS PART OF SHOWPATHS
TODO: 5)FIX REST OF CODEBASE (CS MOSTLY) TO IMPLEMENT THE NEW ASENTRY FORMAT
*/

type Densemetadata struct {
	totaldelay uint16
	totalhops uint8
	maxbw uint32
	links map[addr.IA]ASlink
	locations map[addr.IA]ASgeo
	Notes map[addr.IA]string
}

func (data *Pathmetadata) Condensemetadata() *Densemetadata{
	ret := &Densemetadata{
		totaldelay: 0,
		totalhops: 0,
		maxbw: math.MaxUint32,
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
			ret.maxbw = uint32(math.Min(float64(ret.maxbw),float64(asmaxbw)))
		}
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
	return ret
}

func (solution *PathSolution) Assemblepcbmetadata() *Pathmetadata{
	res := &Pathmetadata{
		Xover : false,
		Peerover : false,
	}
	/*
		iterate over solutionEdges in solution, start in last ASEntry, go until entry with index "shortcut"
		while not shortcut, simply assemble metadata normally using inifid and outifid from the hf in the ASEntry
		and searching for those ifids in the staticinfoextn.
		If index == shortcut, check if "normal" shortcut or peering shortcut (if peer != 0).
		If normal shortcut, do [something]
		If peering shortcut, do [something else]
		Also make sure to treat the first entry in the up and down segs specially.
	*/
	for _, solEdge := range solution.edges{
		asEntries := solEdge.segment.ASEntries
		for asEntryIdx := len(asEntries) - 1; asEntryIdx >= solEdge.edge.Shortcut; asEntryIdx-- {
			if (asEntryIdx>solEdge.edge.Shortcut) {
				asEntry := asEntries[asEntryIdx]
				hopEntry := asEntry.HopEntries[0]
				HF,_ := hopEntry.HopField()
				inIFID := HF.ConsIngress
				//find appropriate values in staticinfoextn
				var SI *seg.StaticInfoExtn
				SI = asEntry.Exts.StaticInfo
				var currdelay ASdelay
				var currhops AShops
				var currlinks ASlink
				var currnotes ASnote
				var currgeo ASgeo
				var currbw ASbw
				var iscoreseg proto.PathSegType
				iscoreseg = proto.PathSegType_core
				if!(asEntryIdx==(len(asEntries)-1)){
					IA := asEntry.IA()
					currdelay.Intradelay = SI.LI.Intooutlatency
					currdelay.IA = IA
					currdelay.Interdelay = SI.LI.Egresslatency
					currdelay.Peerdelay = 0
					currlinks.IA = IA
					currlinks.Interlink = SI.LT.EgressLT
					currlinks.Peerlink = ""
					currbw.IA = IA
					currbw.Interbw = SI.BW.EgressBW
					currbw.Intrabw = SI.BW.IntooutBW
					currbw.Peerbw = 0
					currhops.IA = IA
					currhops.Hops = SI.IH.Intououthops
					currgeo.locations = gathergeo(SI, asEntry)
					currnotes.Note = SI.NI
					res.SingleDelays[IA] = currdelay
					res.SingleHops[IA] = currhops
					res.Singlebw[IA] = currbw
					res.Links[IA] = currlinks
					res.Geo[IA] = currgeo
					res.Notes[IA] = currnotes
				}
				if (solEdge.segment.Type == iscoreseg) && (asEntryIdx==(len(asEntries)-1)) && res.Xover{
					var oldSI *seg.StaticInfoExtn
					IA := res.Overentry.IA()
					oldSI = res.Overentry.Exts.StaticInfo
					currdelay.Intradelay, currdelay.IA = gatherxoverlatency(oldSI, res.Overentry, inIFID)
					currdelay.Interdelay = oldSI.LI.Egresslatency
					currdelay.Peerdelay = 0
					currlinks.IA = IA
					currlinks.Interlink = oldSI.LT.EgressLT
					currlinks.Peerlink = ""
					currbw.IA = IA
					currbw.Interbw = oldSI.BW.EgressBW
					currbw.Intrabw = gatherxoverbw(oldSI, res.Overentry, inIFID)
					currbw.Peerbw = 0
					currhops.IA = IA
					currhops.Hops = gatherxoverhops(oldSI, res.Overentry, inIFID)
					currgeo.locations = gathergeo(oldSI, res.Overentry)
					currnotes.Note = oldSI.NI
					res.SingleDelays[IA] = currdelay
					res.SingleHops[IA] = currhops
					res.Singlebw[IA] = currbw
					res.Links[IA] = currlinks
					res.Geo[IA] = currgeo
					res.Notes[IA] = currnotes
					res.Xover = false
				} else {
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
					currnotes.Note = SI.NI
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
				if(!solEdge.segment.IsDownSeg()) {
					if (solEdge.edge.Peer != 0) {
						peerEntry := asEntry.HopEntries[solEdge.edge.Peer]
						PE, _ := peerEntry.HopField()
						inIFID := PE.ConsIngress
						//treat peering link crossover case
						var currdelay ASdelay
						var currhops AShops
						var currlinks ASlink
						var currnotes ASnote
						var currgeo ASgeo
						var currbw ASbw
						IA := asEntry.IA()
						currdelay.Intradelay, currdelay.Peerdelay, currdelay.IA = gatherpeeringlatencydata(SI, asEntry, inIFID)
						currdelay.Interdelay = SI.LI.Egresslatency
						res.Peerover = true
						res.PeeroverIFID = peerEntry.RemoteInIF
						currlinks.IA = IA
						currlinks.Interlink = SI.LT.EgressLT
						currlinks.Peerlink = gatherpeeroverlink(SI, asEntry, inIFID)
						currbw.IA = IA
						currbw.Interbw = SI.BW.EgressBW
						currbw.Intrabw = gatherxoverbw(SI, asEntry, inIFID)
						currhops.IA = IA
						currhops.Hops = gatherxoverhops(SI, asEntry, inIFID)
						currgeo.locations = gathergeo(SI, asEntry)
						currnotes.Note = SI.NI
						res.SingleDelays[IA] = currdelay
						res.SingleHops[IA] = currhops
						res.Singlebw[IA] = currbw
						res.Links[IA] = currlinks
						res.Geo[IA] = currgeo
						res.Notes[IA] = currnotes
						continue
					} else {
						//treat nonpeering/shortcut crossover phase
						//set Xover flag and save outIFID to OverIFID. Then check at the start of the next segment if
						//Xover is set, if yes, check if core or down seg and consume accordingly (first step for core seg,
						//last step for down seg)
						res.Xover = true
						res.Overentry = asEntry
					}
				} else {
					if(res.Peerover){
						var currdelay ASdelay
						var currhops AShops
						var currlinks ASlink
						var currnotes ASnote
						var currgeo ASgeo
						var currbw ASbw
						IA := asEntry.IA()
						currdelay.Intradelay, currdelay.IA = gatherxoverlatency(SI, asEntry, res.PeeroverIFID)
						currdelay.Interdelay = SI.LI.Egresslatency
						currlinks.IA = IA
						currlinks.Interlink = SI.LT.EgressLT
						currlinks.Peerlink = ""
						currbw.IA = IA
						currbw.Interbw = SI.BW.EgressBW
						currbw.Intrabw = gatherxoverbw(SI, asEntry, res.PeeroverIFID)
						currbw.Peerbw = 0
						currhops.IA = IA
						currhops.Hops = gatherxoverhops(SI, asEntry, res.PeeroverIFID)
						currgeo.locations = gathergeo(SI, asEntry)
						currnotes.Note = SI.NI
						res.SingleDelays[IA] = currdelay
						res.SingleHops[IA] = currhops
						res.Singlebw[IA] = currbw
						res.Links[IA] =  currlinks
						res.Geo[IA] = currgeo
						res.Notes[IA] = currnotes
					}
					if (!res.Peerover && res.Xover){
						var oldSI *seg.StaticInfoExtn
						var currdelay ASdelay
						var currhops AShops
						var currlinks ASlink
						var currnotes ASnote
						var currgeo ASgeo
						var currbw ASbw
						HF,_ := hopEntry.HopField()
						inIFID := HF.ConsEgress
						IA:= res.Overentry.IA()
						oldSI = res.Overentry.Exts.StaticInfo
						currdelay.Intradelay, currdelay.IA = gatherxoverlatency(oldSI, res.Overentry, inIFID)
						currdelay.Interdelay = oldSI.LI.Egresslatency
						currdelay.Peerdelay = SI.LI.Egresslatency
						//we abuse peer delay here for something that isn't technically a peering
						//link but it doesn't really matter
						currlinks.IA = IA
						currlinks.Interlink = oldSI.LT.EgressLT
						currlinks.Peerlink = SI.LT.EgressLT
						currbw.IA = IA
						currbw.Interbw = oldSI.BW.EgressBW
						currbw.Intrabw = gatherxoverbw(oldSI, res.Overentry, inIFID)
						currbw.Peerbw = SI.BW.EgressBW
						currhops.IA = IA
						currhops.Hops = gatherxoverhops(oldSI, res.Overentry, inIFID)
						currgeo.locations = gathergeo(SI, asEntry)
						currnotes.Note = SI.NI
						res.SingleDelays[IA] = currdelay
						res.SingleHops[IA] = currhops
						res.Singlebw[IA] = currbw
						res.Links[IA] = currlinks
						res.Geo[IA] = currgeo
						res.Notes[IA] = currnotes
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
	for i:=0;i< len(SI.LI.Childlatencies);i++{
		if (common.IFIDType(SI.LI.Childlatencies[i].Interface)==inIFID){
			ret1 = SI.LI.Childlatencies[i].Intradelay
			ret2 = asEntry.IA()
		}
	}
	return ret1, ret2
}


func gatherpeeringlatencydata(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) (uint16, uint16, addr.IA){
	var intradelay, interdelay uint16
	var ret3 addr.IA
	for i:=0;i< len(SI.LI.Peeringlatencies);i++{
		if (common.IFIDType(SI.LI.Peeringlatencies[i].IntfID)==inIFID){
			intradelay = SI.LI.Peeringlatencies[i].IntraDelay
			interdelay = SI.LI.Peeringlatencies[i].Interdelay
			ret3 = asEntry.IA()
		}
	}
	return intradelay, interdelay, ret3
}


func gatherpeeroverlink(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) (string){
	var interLT string
	for i:=0;i< len(SI.LT.Peeringlinks);i++{
		if (common.IFIDType(SI.LT.Peeringlinks[i].IntfID)==inIFID){
			interLT = SI.LT.Peeringlinks[i].IntfLT
		}
	}
	return interLT
}


func gatherxoverbw(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) uint32{
	var ret1 uint32
	for i:=0;i< len(SI.BW.BWPairs);i++ {
		if (common.IFIDType(SI.BW.BWPairs[i].IntfID) == inIFID) {
			ret1 = SI.BW.BWPairs[i].BW
		}
	}
	return ret1
}

func gatherxoverhops(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) uint8 {
	var ret1 uint8
	for i := 0; i < len(SI.IH.Hoppairs); i++ {
		if (common.IFIDType(SI.IH.Hoppairs[i].IntfID) == inIFID) {
			ret1 = SI.IH.Hoppairs[i].Hops
		}
	}
	return ret1
}


func gathergeo(SI *seg.StaticInfoExtn, entry *seg.ASEntry) ([]geoloc){
	var ret []geoloc
	for _, geocluster := range SI.GI.Locations{
		var tempcluster geoloc
		tempcluster.Latitude = geocluster.GPSData.Latitude
		tempcluster.Longitude = geocluster.GPSData.Longitude
		tempcluster.CivAddr = geocluster.GPSData.Address
		ret = append(ret, tempcluster)
	}
	return ret
}
