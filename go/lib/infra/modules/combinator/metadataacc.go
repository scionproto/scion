package combinator

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/proto"
)



type ASnote struct {
	Defaultnote string
	Specificnote string
}

type ASgeo struct {
	locations []geoloc
}

type geoloc struct {
	Latitude float32
	Longitude float32
	CivAddr []byte
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
	Intralink string
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
	SingleDelays []ASdelay
	Totaldelay uint16
	Singlebw []ASbw
	Totalbandwidth uint32
	SingleHops []AShops
	Internalhops uint8
	Geo []ASgeo
	Links []ASlink
	Notes []ASnote
	Xover bool
	Overentry *seg.ASEntry
	Peerover bool
	PeeroverIFID common.IFIDType
}


/*
TODO: 1)IMPLEMENT AS PART OF SHOWPATHS
TODO: 2)FIX MESSAGING FOR SCIOND (INCLUDING CAPNP CODE)
TODO: 3)FIX REST OF CODEBASE (CS MOSTLY) TO IMPLEMENT THE NEW ASENTRY FORMAT
 */

type Densemetadata struct {
	totaldelay uint16
	totalhops uint8
	maxbw uint32
	links []ASlink
	locations []ASgeo
	Defaultnotes []string
	Specialnotes []string
}

func (data *Pathmetadata) Condensemetadata() Densemetadata{
	var ret Densemetadata
	ret.totaldelay = 0
	ret.totalhops = 0
	ret.maxbw = 0
	if len(data.Singlebw)>0 {
		if (data.Singlebw[0].Intrabw > 0){
			ret.maxbw = data.Singlebw[0].Intrabw
		}
		if (data.Singlebw[0].Interbw > 0){
			if !(ret.maxbw>0) {
				ret.maxbw = math.MaxUint32-10
			}
			ret.maxbw = uint32(math.Min(float64(data.Singlebw[0].Interbw), float64(ret.maxbw)))
		}
		if (data.Singlebw[0].Peerbw > 0){
			if !(ret.maxbw>0) {
				ret.maxbw = math.MaxUint32-10
			}
			ret.maxbw = uint32(math.Min(float64(data.Singlebw[0].Peerbw), float64(ret.maxbw)))
		}
	}
	for i:=0;i< len(data.SingleDelays);i++{
		ret.totaldelay += data.SingleDelays[i].Interdelay + data.SingleDelays[i].Intradelay + data.SingleDelays[i].Peerdelay
	}
	for i:=0;i< len(data.Singlebw);i++{
		if (data.Singlebw[0].Intrabw > 0){
			if !(ret.maxbw>0) {
				ret.maxbw = math.MaxUint32-10
			}
			ret.maxbw = uint32(math.Min(float64(data.Singlebw[0].Intrabw), float64(ret.maxbw)))
		}
		if (data.Singlebw[0].Interbw > 0){
			if !(ret.maxbw>0) {
				ret.maxbw = math.MaxUint32-10
			}
			ret.maxbw = uint32(math.Min(float64(data.Singlebw[0].Intrabw), float64(ret.maxbw)))
		}
		if (data.Singlebw[0].Peerbw > 0){
			if !(ret.maxbw>0) {
				ret.maxbw = math.MaxUint32-10
			}
			ret.maxbw = uint32(math.Min(float64(data.Singlebw[0].Peerbw), float64(ret.maxbw)))
		}
	}
	for i:=0;i< len(data.SingleHops);i++{
		ret.totalhops += data.SingleHops[i].Hops
	}
	for _,note := range data.Notes{
		ret.Defaultnotes = append(ret.Defaultnotes, note.Defaultnote)
		ret.Specialnotes = append(ret.Specialnotes, note.Specificnote)
	}
	for _,loc := range data.Geo{
		ret.locations = append(ret.locations, loc)
	}
	for _,link := range data.Links{
		ret.links = append(ret.links, link)
	}
	return ret
}

func (solution *PathSolution) Assemblepcbmetadata() Pathmetadata{
	var res Pathmetadata
	res.Xover = false
	res.Peerover = false
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
					currlinks.Intralink = SI.LT.Intooutlt
					currlinks.Peerlink = ""
					currbw.IA = IA
					currbw.Interbw = SI.BW.EgressBW
					currbw.Intrabw = SI.BW.IntooutBW
					currbw.Peerbw = 0
					currhops.IA = IA
					currhops.Hops = SI.IH.Intououthops
					currgeo.locations = gathergeo(SI, asEntry)
					currnotes.Defaultnote = SI.NI.DefaultNote
					currnotes.Specificnote = SI.NI.SpecialNote
					res.SingleDelays = append(res.SingleDelays, currdelay)
					res.SingleHops = append(res.SingleHops, currhops)
					res.Singlebw = append(res.Singlebw, currbw)
					res.Links = append(res.Links, currlinks)
					res.Geo = append(res.Geo, currgeo)
					res.Notes = append(res.Notes, currnotes)
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
					currlinks.Intralink = gatherxoverlink(oldSI, res.Overentry, inIFID)
					currlinks.Peerlink = ""
					currbw.IA = IA
					currbw.Interbw = oldSI.BW.EgressBW
					currbw.Intrabw = gatherxoverbw(oldSI, res.Overentry, inIFID)
					currbw.Peerbw = 0
					currhops.IA = IA
					currhops.Hops = gatherxoverhops(oldSI, res.Overentry, inIFID)
					currgeo.locations = gathergeo(oldSI, res.Overentry)
					currnotes.Defaultnote = oldSI.NI.DefaultNote
					currnotes.Specificnote = oldSI.NI.SpecialNote
					res.SingleDelays = append(res.SingleDelays, currdelay)
					res.SingleHops = append(res.SingleHops, currhops)
					res.Singlebw = append(res.Singlebw, currbw)
					res.Links = append(res.Links, currlinks)
					res.Geo = append(res.Geo, currgeo)
					res.Notes = append(res.Notes, currnotes)
					res.Xover = false
				} else {
					IA := asEntry.IA()
					currdelay.Intradelay = 0
					currdelay.Interdelay = 0
					currdelay.Peerdelay = 0
					currdelay.IA = asEntry.IA()
					currlinks.IA = IA
					currlinks.Interlink = "undisclosed"
					currlinks.Intralink = "undsiclosed"
					currlinks.Peerlink = ""
					currbw.IA = IA
					currbw.Interbw = 0
					currbw.Intrabw = 0
					currbw.Peerbw = 0
					currhops.IA = IA
					currhops.Hops = 0
					currgeo.locations = gathergeo(SI, asEntry)
					currnotes.Defaultnote = SI.NI.DefaultNote
					currnotes.Specificnote = ""
					res.SingleDelays = append(res.SingleDelays, currdelay)
					res.SingleHops = append(res.SingleHops, currhops)
					res.Singlebw = append(res.Singlebw, currbw)
					res.Links = append(res.Links, currlinks)
					res.Geo = append(res.Geo, currgeo)
					res.Notes = append(res.Notes, currnotes)
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
						currlinks.Intralink, currlinks.Peerlink = gatherpeeroverlink(SI, asEntry, inIFID)
						currbw.IA = IA
						currbw.Interbw = SI.BW.EgressBW
						currbw.Intrabw = gatherxoverbw(SI, asEntry, inIFID)
						currhops.IA = IA
						currhops.Hops = gatherxoverhops(SI, asEntry, inIFID)
						currgeo.locations = gathergeo(SI, asEntry)
						currnotes.Defaultnote = SI.NI.DefaultNote
						currnotes.Specificnote = SI.NI.SpecialNote
						res.SingleDelays = append(res.SingleDelays, currdelay)
						res.SingleHops = append(res.SingleHops, currhops)
						res.Singlebw = append(res.Singlebw, currbw)
						res.Links = append(res.Links, currlinks)
						res.Geo = append(res.Geo, currgeo)
						res.Notes = append(res.Notes, currnotes)
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
						currlinks.Intralink = gatherxoverlink(SI, asEntry, res.PeeroverIFID)
						currlinks.Peerlink = ""
						currbw.IA = IA
						currbw.Interbw = SI.BW.EgressBW
						currbw.Intrabw = gatherxoverbw(SI, asEntry, res.PeeroverIFID)
						currbw.Peerbw = 0
						currhops.IA = IA
						currhops.Hops = gatherxoverhops(SI, asEntry, res.PeeroverIFID)
						currgeo.locations = gathergeo(SI, asEntry)
						currnotes.Defaultnote = SI.NI.DefaultNote
						currnotes.Specificnote = SI.NI.SpecialNote
						res.SingleDelays = append(res.SingleDelays, currdelay)
						res.SingleHops = append(res.SingleHops, currhops)
						res.Singlebw = append(res.Singlebw, currbw)
						res.Links = append(res.Links, currlinks)
						res.Geo = append(res.Geo, currgeo)
						res.Notes = append(res.Notes, currnotes)
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
						currlinks.Intralink = gatherxoverlink(oldSI, res.Overentry, inIFID)
						currlinks.Peerlink = SI.LT.EgressLT
						currbw.IA = IA
						currbw.Interbw = oldSI.BW.EgressBW
						currbw.Intrabw = gatherxoverbw(oldSI, res.Overentry, inIFID)
						currbw.Peerbw = SI.BW.EgressBW
						currhops.IA = IA
						currhops.Hops = gatherxoverhops(oldSI, res.Overentry, inIFID)
						currgeo.locations = gathergeo(SI, asEntry)
						currnotes.Defaultnote = SI.NI.DefaultNote
						currnotes.Specificnote = SI.NI.SpecialNote
						res.SingleDelays = append(res.SingleDelays, currdelay)
						res.SingleHops = append(res.SingleHops, currhops)
						res.Singlebw = append(res.Singlebw, currbw)
						res.Links = append(res.Links, currlinks)
						res.Geo = append(res.Geo, currgeo)
						res.Notes = append(res.Notes, currnotes)
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
	for i:=0;i< len(SI.LI.NPClusters);i++{
		for j:=0;j<len(SI.LI.NPClusters[i].Interfaces);j++{
			if (common.IFIDType(SI.LI.NPClusters[i].Interfaces[j])==inIFID){
				ret1 = SI.LI.NPClusters[i].ClusterDelay
				ret2 = asEntry.IA()
			}
		}
	}
	return ret1, ret2
}


func gatherpeeringlatencydata(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) (uint16, uint16, addr.IA){
	var ret1, ret2 uint16
	var ret3 addr.IA
	for i:=0;i< len(SI.LI.PClusters);i++{
		for j:=0;j<len(SI.LI.PClusters[i].PPairs);j++{
			if (common.IFIDType(SI.LI.PClusters[i].PPairs[j].IntfID)==inIFID){
				ret1 = SI.LI.PClusters[i].ClusterDelay
				ret2 = SI.LI.PClusters[i].PPairs[j].IntfDelay
				ret3 = asEntry.IA()
			}
		}
	}
	return ret1, ret2, ret3
}


func gatherxoverlink(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) string{
	var ret1 string
	for i:=0;i< len(SI.LT.NPClusters);i++{
		for j:=0;j<len(SI.LT.NPClusters[i].Interfaces);j++{
			if (common.IFIDType(SI.LT.NPClusters[i].Interfaces[j])==inIFID){
				ret1 = SI.LT.NPClusters[i].ClusterLT
			}
		}
	}
	return ret1
}


func gatherpeeroverlink(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) (string, string){
	var ret1, ret2 string
	for i:=0;i< len(SI.LT.PClusters);i++{
		for j:=0;j<len(SI.LT.PClusters[i].PPairs);j++{
			if (common.IFIDType(SI.LT.PClusters[i].PPairs[j].IntfID)==inIFID){
				ret1 = SI.LT.PClusters[i].ClusterLT
				ret2 = SI.LT.PClusters[i].PPairs[j].IntfLT
			}
		}
	}
	return ret1, ret2
}


func gatherxoverbw(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) uint32{
	var ret1 uint32
	for i:=0;i< len(SI.BW.Clusters);i++ {
		for j := 0; j < len(SI.BW.Clusters[i].Interfaces); j++ {
			if (common.IFIDType(SI.BW.Clusters[i].Interfaces[j]) == inIFID) {
				ret1 = SI.BW.Clusters[i].ClusterBW
			}
		}
	}
	return ret1
}

func gatherxoverhops(SI *seg.StaticInfoExtn, asEntry *seg.ASEntry, inIFID common.IFIDType) uint8 {
	var ret1 uint8
	for i := 0; i < len(SI.IH.HopClusters); i++ {
		for j := 0; j < len(SI.IH.HopClusters[i].IntfIDs); j++ {
			if (common.IFIDType(SI.IH.HopClusters[i].IntfIDs[j]) == inIFID) {
				ret1 = SI.IH.HopClusters[i].ClusterHops
			}
		}
	}
	return ret1
}


func gathergeo(SI *seg.StaticInfoExtn, entry *seg.ASEntry) ([]geoloc){
	var ret []geoloc
	for _, geocluster := range SI.GI.GeoClusters{
		var tempcluster geoloc
		tempcluster.Latitude = geocluster.GL.GPS1
		tempcluster.Longitude = geocluster.GL.GPS2
		tempcluster.CivAddr = geocluster.GL.CivAdd
		ret = append(ret, tempcluster)
	}
	return ret
}
