package seg

import (
	"math"
)

type Latency_Info struct {
	Egresslatency uint16 `capnp: "egresslatency"`
	Intooutlatency uint16 `capnp: "intouutlatency"`
	NPClusters    []LNPCluster
	PClusters     []LPCluster
}

type LNPCluster struct {
	ClusterDelay uint16   `capnp:"clusterdelay"`
	Interfaces   []uint16 `capnp:"interfaces"`
}

type LPPair struct {
	IntfID    uint16 `capnp:"interface"`
	IntfDelay uint16 `capnp:"interdelay"`
}

type LPCluster struct {
	ClusterDelay uint16 `capnp:"clusterdelay"`
	PPairs       []LPPair
}

type Bandwidth_Info struct {
	EgressBW uint32 `capnp:"egressbw"`
	IntooutBW uint32 `capnp: "intooutBW"`
	Clusters []BWCluster
}

type BWCluster struct {
	ClusterBW  uint32   `capnp:"clusterbw"`
	Interfaces []uint16 `capnp:"interfaces"`
}

type Geo_Info struct {
	GeoClusters []GeoCluster
}

type GeoCluster struct {
	GL      ClusterLocation
	IntfIDs []uint16 `capnp:"interfaces"`
}

type ClusterLocation struct {
	GPS1   float32 `capnp:"gps1"`
	GPS2   float32 `capnp:"gps2"`
	CivAdd []byte  `capnp:"civadd"`
}

type Linktype_Info struct {
	EgressLT   string `capnp: "egresslt"`
	Intooutlt string `capnp: "intooutlt"`
	NPClusters []LTNPCluster
	PClusters  []LTPCluster
}

type LTNPCluster struct {
	ClusterLT  string   `capnp:"clusterlt"`
	Interfaces []uint16 `capnp:"interfaces"`
}

type LTPPair struct {
	IntfID uint16 `capnp:"interface"`
	IntfLT string `capnp:"interlt"`
}

type LTPCluster struct {
	ClusterLT string `capnp:"clusterlt"`
	PPairs    []LTPPair
}

type InternalHops_Info struct {
	Intououthops uint8 `capnp: "intoouthops"`
	HopClusters []HopCluster
}

type HopCluster struct {
	ClusterHops uint8    `capnp:"clusterhops"`
	IntfIDs     []uint16 `capnp:"interfaces"`
}

type Note struct {
	SpecialNote string `capnp:"specificnote"`
	DefaultNote string `capnp:"defaultnote"`
}

type StaticInfoExtn struct {
	LI Latency_Info      `capnp:"ei"`
	GI Geo_Info          `capnp:"gi"`
	LT Linktype_Info     `capnp:"lt"`
	BW Bandwidth_Info    `capnp:"bw"`
	IH InternalHops_Info `capnp:"ih"`
	NI Note              `capnp:"ni"`
}

func (latinf *Latency_Info) lc2(somestruct MI2, eintfID uint16, inIFID uint16) {
	var egressLat uint16
	for i := 0; i < len(somestruct.Lat); i++ {
		if somestruct.Lat[i].IntfId == eintfID {
			egressLat = somestruct.Lat[i].Inter
			for j:=0;j<len(somestruct.Lat[i].Intra);j++{
				if (somestruct.Lat[i].Intra[j].IntfId == inIFID) {
					latinf.Intooutlatency = somestruct.Lat[i].Intra[j].Delay
				}
			}
		}
	}
	latinf.Egresslatency = egressLat
	for i := 0; i < len(somestruct.Lat); i++ {
		var assigned = false
		if !(somestruct.Lat[i].Peer) {
			for j := 0; j < len(somestruct.Lat[i].Intra); j++ {
				if (somestruct.Lat[i].IntfId < somestruct.Lat[i].Intra[j].IntfId) && (somestruct.Lat[i].Intra[j].IntfId == eintfID) {
					for k := 0; k < len(latinf.NPClusters); k++ {
						if (somestruct.Lat[i].Intra[j].Delay == latinf.NPClusters[k].ClusterDelay) && (!assigned) {
							latinf.NPClusters[k].Interfaces = append(latinf.NPClusters[k].Interfaces, somestruct.Lat[i].IntfId)
							assigned = true
						}
					}
					if !assigned {
						var asdf LNPCluster
						asdf.ClusterDelay = somestruct.Lat[i].Intra[j].Delay
						asdf.Interfaces = append(asdf.Interfaces, somestruct.Lat[i].IntfId)
						latinf.NPClusters = append(latinf.NPClusters, asdf)
						assigned = true
					}
				}

			}
		} else {
			for j := 0; j < len(somestruct.Lat[i].Intra); j++ {
				if (somestruct.Lat[i].IntfId < somestruct.Lat[i].Intra[j].IntfId) && (somestruct.Lat[i].Intra[j].IntfId == eintfID) {
					for k := 0; k < len(latinf.PClusters); k++ {
						if (somestruct.Lat[i].Intra[j].Delay == latinf.PClusters[k].ClusterDelay) && (!assigned) {
							var provpair LPPair
							provpair.IntfID = somestruct.Lat[i].IntfId
							provpair.IntfDelay = somestruct.Lat[i].Inter
							latinf.PClusters[k].PPairs = append(latinf.PClusters[k].PPairs, provpair)
							assigned = true
						}
					}
					if !assigned {
						var asdf LPCluster
						var provpair LPPair
						provpair.IntfID = somestruct.Lat[i].IntfId
						provpair.IntfDelay = somestruct.Lat[i].Inter
						asdf.PPairs = append(asdf.PPairs, provpair)
						asdf.ClusterDelay = somestruct.Lat[i].Intra[j].Delay
						latinf.PClusters = append(latinf.PClusters, asdf)
						assigned = true
					}
				}
			}
		}
	}
}

func (bwinf *Bandwidth_Info) bwc2(somestruct MI2, eintfID uint16, inIFID uint16) {
	var egressBW uint32
	for i := 0; i < len(somestruct.BW); i++ {
		if somestruct.BW[i].IntfId == eintfID {
			egressBW = somestruct.BW[i].Inter
			for j:=0;j<len(somestruct.BW[i].Intra);j++{
				if (somestruct.BW[i].Intra[j].IntfId == inIFID) {
					bwinf.IntooutBW = somestruct.BW[i].Intra[j].BWintra
				}
			}
		}
	}
	bwinf.EgressBW = egressBW
	for i := 0; i < len(somestruct.BW); i++ {
		var assigned = false
		var actualbw uint32
		for j := 0; j < len(somestruct.BW[i].Intra); j++ {
			if (somestruct.BW[i].Intra[j].IntfId == eintfID) && (somestruct.BW[i].IntfId < somestruct.BW[i].Intra[j].IntfId) {
				if somestruct.BW[i].Peer {
					actualbw = uint32(math.Min(float64(somestruct.BW[i].Intra[j].BWintra), float64(somestruct.BW[i].Inter)))
				} else {
					actualbw = somestruct.BW[i].Intra[j].BWintra
				}
				for k := 0; k < len(bwinf.Clusters); k++ {
					if (actualbw >= bwinf.Clusters[k].ClusterBW-5) && (actualbw < bwinf.Clusters[k].ClusterBW+5) && (!assigned) {
						bwinf.Clusters[k].Interfaces = append(bwinf.Clusters[k].Interfaces, somestruct.BW[i].IntfId)
						assigned = true
					}
				}
				if !assigned {
					var asdf BWCluster
					asdf.ClusterBW = actualbw
					asdf.Interfaces = append(asdf.Interfaces, somestruct.BW[i].IntfId)
					bwinf.Clusters = append(bwinf.Clusters, asdf)
					assigned = true
				}
			}
		}
	}
}

func (ltinf *Linktype_Info) ltc2(somestruct MI2, eintfID uint16, inIFID uint16) {
	var egressLT string
	for i := 0; i < len(somestruct.LT); i++ {
		if somestruct.LT[i].IntfId == eintfID {
			egressLT = somestruct.LT[i].Inter
			for j:=0;j<len(somestruct.LT[i].Intra);j++{
				if (somestruct.LT[i].Intra[j].IntfId == inIFID) {
					ltinf.Intooutlt = somestruct.LT[i].Intra[j].LT
				}
			}
		}
	}
	ltinf.EgressLT = egressLT
	for i := 0; i < len(somestruct.LT); i++ {
		var assigned = false
		if !(somestruct.LT[i].Peer) {
			for j := 0; j < len(somestruct.LT[i].Intra); j++ {
				if (somestruct.LT[i].IntfId < somestruct.LT[i].Intra[j].IntfId) && (somestruct.LT[i].Intra[j].IntfId == eintfID) {
					for k := 0; k < len(ltinf.NPClusters); k++ {
						if (somestruct.LT[i].Intra[j].LT == ltinf.NPClusters[k].ClusterLT) && (!assigned) {
							ltinf.NPClusters[k].Interfaces = append(ltinf.NPClusters[k].Interfaces, somestruct.LT[i].IntfId)
							assigned = true
						}
					}
					if !assigned {
						var asdf LTNPCluster
						asdf.ClusterLT = somestruct.LT[i].Intra[j].LT
						asdf.Interfaces = append(asdf.Interfaces, somestruct.LT[i].IntfId)
						ltinf.NPClusters = append(ltinf.NPClusters, asdf)
						assigned = true
					}
				}
			}
		} else {
			for j := 0; j < len(somestruct.LT[i].Intra); j++ {
				if (somestruct.LT[i].IntfId < somestruct.LT[i].Intra[j].IntfId) && (somestruct.LT[i].Intra[j].IntfId == eintfID) {
					for k := 0; k < len(ltinf.PClusters); k++ {
						if (somestruct.LT[i].Intra[j].LT == ltinf.PClusters[k].ClusterLT) && (!assigned) {
							var provpair LTPPair
							provpair.IntfID = somestruct.LT[i].IntfId
							provpair.IntfLT = somestruct.LT[i].Inter
							ltinf.PClusters[k].PPairs = append(ltinf.PClusters[k].PPairs, provpair)
							assigned = true
						}
					}
					if !assigned {
						var asdf LTPCluster
						var provpair LTPPair
						provpair.IntfID = somestruct.LT[i].IntfId
						provpair.IntfLT = somestruct.LT[i].Inter
						asdf.PPairs = append(asdf.PPairs, provpair)
						asdf.ClusterLT = somestruct.LT[i].Intra[j].LT
						ltinf.PClusters = append(ltinf.PClusters, asdf)
						assigned = true
					}
				}
			}
		}
	}
}

func (nhinf *InternalHops_Info) nhc2(somestruct MI2, eintfID uint16, inIFID uint16){
	for i := 0; i < len(somestruct.Hops); i++ {
		var assigned = false
		if somestruct.Hops[i].IntfId == inIFID {
			for j := 0; j < len(somestruct.Hops[i].Intra); j++ {
				if (somestruct.Hops[i].Intra[j].IntfId == inIFID) {
					nhinf.Intououthops = somestruct.Hops[i].Intra[j].HN
				}
			}
		}
		for j := 0; j < len(somestruct.Hops[i].Intra); j++ {
			if (somestruct.Hops[i].IntfId < somestruct.Hops[i].Intra[j].IntfId) && (somestruct.Hops[i].Intra[j].IntfId == eintfID) {
				for k := 0; k < len(nhinf.HopClusters); k++ {
					if (somestruct.Hops[i].Intra[j].HN == nhinf.HopClusters[k].ClusterHops) && (!assigned) {
						nhinf.HopClusters[k].IntfIDs = append(nhinf.HopClusters[k].IntfIDs, somestruct.Hops[i].IntfId)
						assigned = true
					}
				}
				if !assigned {
					var asdf HopCluster
					asdf.ClusterHops = somestruct.Hops[i].Intra[j].HN
					asdf.IntfIDs = append(asdf.IntfIDs, somestruct.Hops[i].IntfId)
					nhinf.HopClusters = append(nhinf.HopClusters, asdf)
					assigned = true
				}
			}
		}
	}
}

func (geoinf *Geo_Info) gc2(somestruct MI2, eintfID uint16) {
	for i := 0; i < len(somestruct.Geo); i++ {
		var assigned = false
		for k := 0; k < len(geoinf.GeoClusters); k++ {
			if (somestruct.Geo[i].C1 >= geoinf.GeoClusters[k].GL.GPS1-0.0005) && (somestruct.Geo[i].C1 < geoinf.GeoClusters[k].GL.GPS1+0.0005) && ((somestruct.Geo[i].C2 >= geoinf.GeoClusters[k].GL.GPS2-0.0005) && (somestruct.Geo[i].C2 < geoinf.GeoClusters[k].GL.GPS2+0.0005)) && (!assigned) {
				geoinf.GeoClusters[k].IntfIDs = append(geoinf.GeoClusters[k].IntfIDs, somestruct.Geo[i].ID)
				assigned = true
			}
		}
		if !assigned {
			var asdf GeoCluster
			asdf.GL.GPS1 = somestruct.Geo[i].C1
			asdf.GL.GPS2 = somestruct.Geo[i].C2
			asdf.GL.CivAdd = somestruct.Geo[i].CivAddr
			asdf.IntfIDs = append(asdf.IntfIDs, somestruct.Geo[i].ID)
			geoinf.GeoClusters = append(geoinf.GeoClusters, asdf)
			assigned = true
		}
	}
}

func (noteinf *Note) na2(somestruct MI2, eintfid uint16) {
	noteinf.DefaultNote = somestruct.N.Default
	for i := 0; i < len(somestruct.N.Specific); i++ {
		if somestruct.N.Specific[i].IntfId == eintfid {
			noteinf.SpecialNote = somestruct.N.Specific[i].Msg
		}
	}
}
