package combinator

import (
	"time"

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

	// Geo lists the geographical position of the border routers along the path.
	// Entry i describes the position of the router for interface i.
	// A 0-value indicates that the AS did not announce a position for this router.
	Geo []GeoCoordinates

	// Bandwidth lists the bandwidth between any two consecutive interfaces.
	// Entry i describes the bandwidth between interfaces i and i+1.
	// A 0-value indicates that the AS did not announce a bandwidth for this hop.
	Bandwidth []uint

	// LinkType contains the announced link type of inter-domain links.
	// Entry i describes the link between interfaces 2*i and 2*i+1.
	LinkTypes []LinkType

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
	Interfaces []snet.PathInterface // PathInterfaces, in order of occurrence on the path
	ASEntries  []seg.ASEntry        // ASEntries, in order of occurrence on the path
}

func collectMetadata(interfaces []snet.PathInterface, asEntries []seg.ASEntry) PathMetadata {
	path := pathInfo{interfaces, asEntries}
	return PathMetadata{
		Latency: collectLatency(path),
		Geo:     collectGeo(path),
		Notes:   collectNotes(path),
	}
}

func collectLatency(path pathInfo) []time.Duration {
	// Were making our lives quite easy here:
	// 0) Prepare lookup table of the connected remote interface ID; this is not
	//    directly available from the individual AS entries (except for peers, but
	//    this way we don't even have to care).
	// 1) Go over the ASEntries (in whatever order) and store the latency
	//    information for any interface pair we can find to a map.
	//    Here, we can also handle any inconsistencies we may find.
	// 2) Go over the path, in order, for each pair of consecutive interfaces, we
	//    just lookiup the latency from the map.

	// 0)
	remoteIF := make(map[snet.PathInterface]snet.PathInterface)
	for i := 0; i < len(path.Interfaces); i += 2 {
		remoteIF[path.Interfaces[i]] = path.Interfaces[i+1]
		remoteIF[path.Interfaces[i+1]] = path.Interfaces[i]
	}

	// 1)
	hopLatencies := make(map[hopKey]time.Duration)
	for _, asEntry := range path.ASEntries {
		staticInfo := asEntry.Extensions.StaticInfo
		if staticInfo != nil && staticInfo.Latency != nil {
			inIF := snet.PathInterface{
				IA: asEntry.Local,
				ID: common.IFIDType(asEntry.HopEntry.HopField.ConsIngress),
			}
			egIF := snet.PathInterface{
				IA: asEntry.Local,
				ID: common.IFIDType(asEntry.HopEntry.HopField.ConsEgress),
			}
			latency := staticInfo.Latency
			// Ingress to Egress interface
			addHopLatency(hopLatencies, inIF, egIF, latency.Intra)
			// Egress to neighbor
			addHopLatency(hopLatencies, egIF, remoteIF[egIF], latency.Inter)
			// Egress to sibling child, core or peer interfaces
			for ifid, v := range latency.XoverIntra {
				xoverIF := snet.PathInterface{IA: asEntry.Local, ID: ifid}
				addHopLatency(hopLatencies, egIF, xoverIF, v)
			}
			// Local peer to remote peer interface
			for ifid, v := range latency.PeerInter {
				localIF := snet.PathInterface{IA: asEntry.Local, ID: ifid}
				addHopLatency(hopLatencies, localIF, remoteIF[localIF], v)
			}
		}
	}

	// 2)
	latencies := make([]time.Duration, len(path.Interfaces)-1)
	for i := 0; i+1 < len(path.Interfaces); i++ {
		latencies[i] = hopLatencies[makeHopKey(path.Interfaces[i], path.Interfaces[i+1])]
	}

	return latencies
}

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

func collectGeo(path pathInfo) []GeoCoordinates {
	geos := make([]GeoCoordinates, len(path.Interfaces))
	for i, iface := range path.Interfaces {
		asEntry := path.ASEntries[(i+1)/2] // ugh
		staticInfo := asEntry.Extensions.StaticInfo
		if staticInfo != nil && staticInfo.Geo != nil {
			geos[i] = GeoCoordinates(staticInfo.Geo[iface.ID])
		}
	}
	return geos
}

func collectNotes(path pathInfo) []string {
	notes := make([]string, len(path.ASEntries))
	for i, asEntry := range path.ASEntries {
		staticInfo := asEntry.Extensions.StaticInfo
		if staticInfo != nil {
			notes[i] = staticInfo.Note
		}
	}
	return notes
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
