package fetcher

import (
	"math"

	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/sciond"
)

// Condensemetadata takes RawPathMetadata and extracts/condenses
// the most important values to be transmitted to SCIOND
func CondenseMetadata(data *combinator.PathMetadata) *sciond.PathMetadata {
	ret := &sciond.PathMetadata{
		Latency: 0,
		Hops:    0,
		Bandwidth:  math.MaxUint32,
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
			ret.Bandwidth = min(ret.Bandwidth, asmaxbw)
		}
	}

	if ret.Bandwidth == math.MaxUint32 {
		ret.Bandwidth = 0
	}

	for _, val := range data.ASLatencies {
		ret.Latency += val.InterLatency + val.IntraLatency + val.PeerLatency
	}

	for _, val := range data.ASHops {
		ret.Hops += val.Hops
	}

	for ia, note := range data.Notes {
		ret.Notes = append(ret.Notes, &sciond.Note{
			Note:  note.Note,
			RawIA: ia.IAInt(),
		})
	}

	for ia, loc := range data.Geo {
		newloc := sciond.Geo{
			RouterLocations: []*sciond.GeoLoc{},
			RawIA:           ia.IAInt(),
		}
		for _, gpsdata := range loc.Locations {
			newloc.RouterLocations = append(newloc.RouterLocations,
				&sciond.GeoLoc{
					Latitude:  gpsdata.Latitude,
					Longitude: gpsdata.Longitude,
					Address:   gpsdata.Address,
				})
		}
		ret.Geos = append(ret.Geos, &newloc)
	}

	for _, link := range data.Links {
		if sciond.LinkType(link.InterLinkType) != sciond.LinkTypeUnset{
			ret.LinkTypes = append(ret.LinkTypes, sciond.LinkType(link.InterLinkType))
		}
		if sciond.LinkType(link.PeerLinkType) != sciond.LinkTypeUnset{
			ret.LinkTypes = append(ret.LinkTypes, sciond.LinkType(link.PeerLinkType))
		}
		if (sciond.LinkType(link.InterLinkType) == sciond.LinkTypeUnset) &&
			(sciond.LinkType(link.PeerLinkType) == sciond.LinkTypeUnset){
			ret.LinkTypes = append(ret.LinkTypes, sciond.LinkTypeUnset)
		}
	}

	return ret
}

func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
