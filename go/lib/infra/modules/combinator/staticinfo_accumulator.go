package combinator

import (
	"fmt"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/snet"
)

// XXX(matzf) these types are only here temporarily, to keep changes localized for the current PR.
// This will be moved to snet.PathMetadata, making this available to applications.

// TODO(matzf) document where does this info come from and how much to trust it.
type PathMetadata struct {
	// Latency lists the latencies between any two consecutive interfaces.
	// Entry i describes the latency between interface i and i+1.
	// Consequently, there are N-1 entries for N interfaces.
	// A 0-value indicates that the AS did not announce a latency for this hop.
	Latency []time.Duration

	// Bandwidth lists the bandwidth between any two consecutive interfaces.
	// Entry i describes the bandwidth between interfaces i and i+1.
	// A 0-value indicates that the AS did not announce a bandwidth for this hop.
	Bandwidth []uint32

	// Geo lists the geographical position of the border routers along the path.
	// Entry i describes the position of the router for interface i.
	// A 0-value indicates that the AS did not announce a position for this router.
	Geo []GeoCoordinates

	// LinkType contains the announced link type of inter-domain links.
	// Entry i describes the link between interfaces 2*i and 2*i+1.
	LinkType []LinkType

	// InternalHops lists the number of AS internal hops for the ASes on path.
	// Entry i describes the hop between interfaces 2*i+1 and 2*i+2 in the same AS.
	// Consequently, there are no entries for the first and last ASes, as these
	// are not traversed completely by the path.
	InternalHops []uint32

	// Notes contains the notes added by ASes on the path, in the order of occurrence.
	// Entry i is the note of AS i on the path.
	Notes []string
}

type LinkType uint8

const (
	LinkTypeUnset LinkType = iota
	LinkTypeDirect
	LinkTypeMultihop
	LinkTypeOpennet
)

type GeoCoordinates seg.GeoCoordinates

// pathInfo is a helper to extract the StaticInfo metadata, using the information
// of the path already created from the pathSolution.
type pathInfo struct {
	// Interfaces contains the PathInterfaces in order of occurrence on the path.
	Interfaces []snet.PathInterface
	// ASEntries contains the relevant ASEntries (in arbitrary order)
	ASEntries []seg.ASEntry
	// RemoteIF is a lookup table for connected remote interface.
	// This information is otherwise not directly available from the individual
	// AS (except for peers, but this way we don't even have to care).
	RemoteIF map[snet.PathInterface]snet.PathInterface
}

func collectMetadata(interfaces []snet.PathInterface, asEntries []seg.ASEntry) PathMetadata {
	if len(interfaces) == 0 {
		return PathMetadata{}
	}
	if len(interfaces)%2 != 0 {
		panic("the number of interfaces traversed by the path is expected to be even")
	}

	// Prepare lookup table of the connected remote interface IDs; this is not
	// directly available from the individual AS entries (except for peers, but
	// this way we don't even have to care).
	remoteIF := make(map[snet.PathInterface]snet.PathInterface)
	for i := 0; i < len(interfaces); i += 2 {
		remoteIF[interfaces[i]] = interfaces[i+1]
		remoteIF[interfaces[i+1]] = interfaces[i]
	}

	path := pathInfo{interfaces, asEntries, remoteIF}
	return PathMetadata{
		Latency:      collectLatency(path),
		Bandwidth:    collectBandwidth(path),
		Geo:          collectGeo(path),
		LinkType:     collectLinkType(path),
		InternalHops: collectInternalHops(path),
		Notes:        collectNotes(path),
	}
}

func collectLatency(p pathInfo) []time.Duration {
	// Were making our lives quite easy here:
	// 1) Go over the ASEntries (in whatever order) and store the latency
	//    information for any interface pair we can find to a map.
	//    Here, we can also handle any inconsistencies we may find.
	// 2) Go over the path, in order, for each pair of consecutive interfaces, we
	//    just lookiup the latency from the map.

	// 1)
	hopLatencies := make(map[hopKey]time.Duration)
	for _, asEntry := range p.ASEntries {
		staticInfo := asEntry.Extensions.StaticInfo
		if staticInfo != nil && staticInfo.Latency != nil {
			egIF := snet.PathInterface{
				IA: asEntry.Local,
				ID: common.IFIDType(asEntry.HopEntry.HopField.ConsEgress),
			}
			latency := staticInfo.Latency
			// Egress to sibling child, core or peer interfaces
			for ifid, v := range latency.Intra {
				otherIF := snet.PathInterface{IA: asEntry.Local, ID: ifid}
				addHopLatency(hopLatencies, egIF, otherIF, v)
			}
			// Local peer to remote peer interface
			for ifid, v := range latency.Inter {
				localIF := snet.PathInterface{IA: asEntry.Local, ID: ifid}
				addHopLatency(hopLatencies, localIF, p.RemoteIF[localIF], v)
			}
		}
	}

	// 2)
	latencies := make([]time.Duration, len(p.Interfaces)-1)
	for i := 0; i+1 < len(p.Interfaces); i++ {
		latencies[i] = hopLatencies[makeHopKey(p.Interfaces[i], p.Interfaces[i+1])]
	}

	return latencies
}

// addHopLatency adds the latency of hop a-b to the map. Handle conflicting entries by
// chosing the more conservative value (i.e. keep higher latency value).
func addHopLatency(m map[hopKey]time.Duration, a, b snet.PathInterface, v time.Duration) {
	// Skip incomplete entries; not strictly necessary, we'd just not look this up
	if a.ID == 0 || b.ID == 0 {
		return
	}
	if v == 0 {
		return
	}
	k := makeHopKey(a, b)
	if vExisting, exists := m[k]; !exists || vExisting < v {
		m[k] = v
	}
}

func collectBandwidth(p pathInfo) []uint32 {
	// This is identical to collecting latencies.
	// 1)
	hopBandwidths := make(map[hopKey]uint32)
	for _, asEntry := range p.ASEntries {
		staticInfo := asEntry.Extensions.StaticInfo
		if staticInfo != nil && staticInfo.Bandwidth != nil {
			egIF := snet.PathInterface{
				IA: asEntry.Local,
				ID: common.IFIDType(asEntry.HopEntry.HopField.ConsEgress),
			}
			bandwidth := staticInfo.Bandwidth
			// Egress to other local interfaces
			for ifid, v := range bandwidth.Intra {
				otherIF := snet.PathInterface{IA: asEntry.Local, ID: ifid}
				addHopBandwidth(hopBandwidths, egIF, otherIF, v)
			}
			// Local peer to remote peer interface
			for ifid, v := range bandwidth.Inter {
				localIF := snet.PathInterface{IA: asEntry.Local, ID: ifid}
				addHopBandwidth(hopBandwidths, localIF, p.RemoteIF[localIF], v)
			}
		}
	}

	// 2)
	bandwidths := make([]uint32, len(p.Interfaces)-1)
	for i := 0; i+1 < len(p.Interfaces); i++ {
		bandwidths[i] = hopBandwidths[makeHopKey(p.Interfaces[i], p.Interfaces[i+1])]
	}

	return bandwidths
}

// addHopBandwidth adds the bandwidth of hop a-b to the map. Handle conflicting entries by
// chosing the more conservative value (i.e. keep lower bandwidth value).
func addHopBandwidth(m map[hopKey]uint32, a, b snet.PathInterface, v uint32) {
	// Skip incomplete entries; not strictly necessary, we'd just not look this up
	if a.ID == 0 || b.ID == 0 {
		return
	}
	if v == 0 {
		return
	}
	k := makeHopKey(a, b)
	if vExisting, exists := m[k]; !exists || vExisting > v {
		m[k] = v
	}
}

func collectGeo(p pathInfo) []GeoCoordinates {
	ifaceGeos := make(map[snet.PathInterface]GeoCoordinates)
	for _, asEntry := range p.ASEntries {
		staticInfo := asEntry.Extensions.StaticInfo
		if staticInfo != nil && staticInfo.Geo != nil {
			for ifid, v := range staticInfo.Geo {
				iface := snet.PathInterface{IA: asEntry.Local, ID: ifid}
				ifaceGeos[iface] = GeoCoordinates(v)
			}
		}
	}

	geos := make([]GeoCoordinates, len(p.Interfaces))
	for i, iface := range p.Interfaces {
		geos[i] = ifaceGeos[iface]
	}
	return geos
}

func collectLinkType(p pathInfo) []LinkType {
	// 1) Gather map with all the LinkTypes, identified by the (unordered)
	// interface pair associated with each link
	hopLinkTypes := make(map[hopKey]LinkType)
	for _, asEntry := range p.ASEntries {
		staticInfo := asEntry.Extensions.StaticInfo
		if staticInfo != nil {
			for ifid, rawLinkType := range staticInfo.LinkType {
				linkType := linkTypeFromSeg(rawLinkType)
				localIF := snet.PathInterface{IA: asEntry.Local, ID: ifid}
				hop := makeHopKey(localIF, p.RemoteIF[localIF])
				if prevLinkType, duplicate := hopLinkTypes[hop]; duplicate {
					// Handle conflicts by using LinkTypeUnset
					if prevLinkType != linkType {
						hopLinkTypes[hop] = LinkTypeUnset
					}
				} else {
					hopLinkTypes[hop] = linkType
				}
			}
		}
	}

	fmt.Println("hopLinkTypes", hopLinkTypes)
	// 2) Go over the path; for each inter-AS link interface pair, add the link type
	linkTypes := make([]LinkType, len(p.Interfaces)/2)
	for i := 0; i < len(p.Interfaces); i += 2 {
		linkTypes[i/2] = hopLinkTypes[makeHopKey(p.Interfaces[i], p.Interfaces[i+1])]
	}
	return linkTypes
}

func linkTypeFromSeg(lt seg.LinkType) LinkType {
	switch lt {
	case seg.LinkTypeDirect:
		return LinkTypeDirect
	case seg.LinkTypeMultihop:
		return LinkTypeMultihop
	case seg.LinkTypeOpennet:
		return LinkTypeOpennet
	default:
		return LinkTypeUnset
	}
}

func collectInternalHops(p pathInfo) []uint32 {
	// Analogous to collectLatencies, but simplified as there are no inter-AS
	// hops to worry about.

	// 1)
	// Note: the odd name means "number of internal hops, indexed by the hop(-key)".
	// Just to keep this consistent with e.g. hopLatencies, which sounds a lot
	// less weird.
	hopInternalHops := make(map[hopKey]uint32)
	for _, asEntry := range p.ASEntries {
		staticInfo := asEntry.Extensions.StaticInfo
		egIF := snet.PathInterface{
			IA: asEntry.Local,
			ID: common.IFIDType(asEntry.HopEntry.HopField.ConsEgress),
		}
		if staticInfo != nil && egIF.ID != 0 {
			internalHops := staticInfo.InternalHops
			for ifid, v := range internalHops {
				otherIF := snet.PathInterface{IA: asEntry.Local, ID: ifid}
				addHopInternalHops(hopInternalHops, egIF, otherIF, v)
			}
		}
	}

	// 2) Now add an entry for each fully traversed AS
	internalHops := make([]uint32, (len(p.Interfaces)-2)/2)
	for i := 1; i+1 < len(p.Interfaces); i += 2 {
		internalHops[(i-1)/2] = hopInternalHops[makeHopKey(p.Interfaces[i], p.Interfaces[i+1])]
	}

	return internalHops
}

func addHopInternalHops(m map[hopKey]uint32, a, b snet.PathInterface, v uint32) {
	// behaviour is identical to bandwidth.
	addHopBandwidth(m, a, b, v)
}

func collectNotes(p pathInfo) []string {
	// can have multiple AS entries for the same AS (at segment cross over, or loop paths).
	// collect all notes first
	allNotes := make(map[addr.IA][]string)
	for _, asEntry := range p.ASEntries {
		ia := asEntry.Local
		staticInfo := asEntry.Extensions.StaticInfo
		if staticInfo != nil && len(staticInfo.Note) > 0 {
			allNotes[ia] = append(allNotes[ia], staticInfo.Note)
		}
	}

	// (very) explicitly gather traversed ASes from path interface list
	ases := []addr.IA{}
	ases = append(ases, p.Interfaces[0].IA)
	for i := 1; i < len(p.Interfaces); i += 2 {
		ases = append(ases, p.Interfaces[i].IA)
	}

	// Now put the notes in order. Deduplicate entries but keep multiple notes in
	// case there are differences.
	notes := make([]string, len(ases))
	for i, ia := range ases {
		asNotes := deduplicateStrings(allNotes[ia])
		notes[i] = strings.Join(asNotes, "\n")
	}
	return notes
}

func deduplicateStrings(elements []string) []string {
	result := []string{}
	for _, v := range elements {
		exists := false
		for _, r := range result {
			if v == r {
				exists = true
				break
			}
		}
		if !exists {
			result = append(result, v)
		}
	}
	return result
}

// hopKey is a map key for looking up information about a hop, a pair of
// snet.PathInterface.
type hopKey struct {
	a snet.PathInterface
	b snet.PathInterface
}

// makeHopKey makes a key for an unordered interface pair lookup.
func makeHopKey(a, b snet.PathInterface) hopKey {
	if a.IA.IAInt() > b.IA.IAInt() || a.IA == b.IA && a.ID > b.ID {
		return hopKey{b, a}
	}
	return hopKey{a, b}
}
