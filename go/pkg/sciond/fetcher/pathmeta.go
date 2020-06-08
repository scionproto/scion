package fetcher

import (
	"math"

	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/sciond"
)

// Condensemetadata takes RawPathMetadata and extracts/condenses
// the most important values to be transmitted to SCIOND
func Condensemetadata(data *combinator.PathMetadata) *sciond.PathMetadata {
	ret := &sciond.PathMetadata{
		TotalLatency: 0,
		TotalHops:    0,
		MinOfMaxBWs:  math.MaxUint32,
	}

	for _, val := range data.ASBandwidths {
		var asmaxbw uint32 = math.MaxUint32
		if val.IntraBW > 0 {
			asmaxbw = min(val.IntraBW, asmaxbw)
		}
		if val.InterBW > 0 {
			asmaxbw = min(val.InterBW, asmaxbw)
		}
		if asmaxbw < math.MaxUint32 {
			ret.MinOfMaxBWs = min(ret.MinOfMaxBWs, asmaxbw)
		}
	}

	if ret.MinOfMaxBWs == math.MaxUint32 {
		ret.MinOfMaxBWs = 0
	}

	for _, val := range data.ASLatencies {
		ret.TotalLatency += val.InterLatency + val.IntraLatency + val.PeerLatency
	}

	for _, val := range data.ASHops {
		ret.TotalHops += val.Hops
	}

	for ia, note := range data.Notes {
		ret.Notes = append(ret.Notes, &sciond.DenseNote{
			Note:  note.Note,
			RawIA: ia.IAInt(),
		})
	}

	for ia, loc := range data.Geo {
		newloc := sciond.DenseGeo{
			RouterLocations: []*sciond.DenseGeoLoc{},
			RawIA:           ia.IAInt(),
		}
		for _, gpsdata := range loc.Locations {
			newloc.RouterLocations = append(newloc.RouterLocations,
				&sciond.DenseGeoLoc{
					Latitude:  gpsdata.Latitude,
					Longitude: gpsdata.Longitude,
					Address:   gpsdata.Address,
				})
		}
		ret.Locations = append(ret.Locations, &newloc)
	}

	for ia, link := range data.Links {
		ret.LinkTypes = append(ret.LinkTypes, &sciond.DenseASLinkType{
			InterLinkType: link.InterLinkType,
			PeerLinkType:  link.PeerLinkType,
			RawIA:         ia.IAInt(),
		})
	}

	return ret
}

func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
