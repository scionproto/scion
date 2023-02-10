// Copyright 2018 ETH Zurich, Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package combinator contains methods for constructing SCION forwarding paths.
//
// Call Combine to grab all the metadata associated with the constructed paths.
//
// Returned paths are sorted by weight in descending order. The weight is
// defined as the number of transited AS hops in the path.
package combinator

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"

	"github.com/scionproto/scion/pkg/addr"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

// Combine constructs paths between src and dst using the supplied
// segments. All possible paths are first computed, and then filtered according
// to filterLongPaths.
//
// Normally, with findAllIdentical=false, Combine returns one path for each
// unique sequence of path interfaces found. If there are multiple ways to
// construct the same sequence of path interfaces from the available path
// segments, the construction with latest expiration time will be returned.
//
// With findAllIdentical=true, Combine may return multiple paths with identical
// sequences of path interfaces, but constructed from different path segments.
// These forwarding paths can only be destinguished by the segment IDs and the
// hop field MACs. Typically, all of these will have exactly the same
// forwarding behaviour, but it is possible that an AS would misbehave and
// change behaviour based on the segment IDs or MACs. An application can use
// findAllIdentical=true in order to explore whether this may be the case.
// Note that this may return a large number of paths for wide network
// topologies.
//
// The remaining paths are returned sorted according to
// weight (on equal weight, see pathSolutionList.Less for the tie-breaking
// algorithm).
//
// If Combine cannot extract a hop field or info field from the segments, it
// panics.
func Combine(src, dst addr.IA, ups, cores, downs []*seg.PathSegment,
	findAllIdentical bool) []Path {

	solutions := newDMG(ups, cores, downs).GetPaths(vertexFromIA(src), vertexFromIA(dst))
	paths := make([]Path, len(solutions))
	for i, solution := range solutions {
		paths[i] = solution.Path()
	}
	paths = filterLongPaths(paths)
	if !findAllIdentical {
		paths = filterDuplicates(paths)
	}
	return paths
}

type Path struct {
	Dst       addr.IA
	SCIONPath path.SCION
	Metadata  snet.PathMetadata
	Weight    int // XXX(matzf): unused, drop this?
}

// filterLongPaths returns a new slice containing only those paths that do not
// go more than twice through interfaces belonging to the same AS (thus
// filtering paths containing useless loops).
func filterLongPaths(paths []Path) []Path {
	var newPaths []Path
	for _, path := range paths {
		long := false
		iaCounts := make(map[addr.IA]int)
		for _, iface := range path.Metadata.Interfaces {
			iaCounts[iface.IA]++
			if iaCounts[iface.IA] > 2 {
				long = true
				break
			}
		}
		if !long {
			newPaths = append(newPaths, path)
		}
	}
	return newPaths
}

// filterDuplicates removes paths with identical sequences of path interfaces,
// keeping only the one instance with latest expiry.
// Duplicates can arise when multiple combinations of different path segments
// result in the same "effective" path after applying short-cuts.
// XXX(matzf): the duplicates could/should be avoided directly by reducing the
// available options in the graph, as we could potentially create a large
// number of duplicates in wide network topologies.
func filterDuplicates(paths []Path) []Path {
	// uniquePaths stores the index of the path with the latest expiry for every
	// unique path interface sequence (== fingerprint).
	uniquePaths := make(map[snet.PathFingerprint]int)
	for i, p := range paths {
		key := fingerprint(p.Metadata.Interfaces)
		prev, dupe := uniquePaths[key]
		if !dupe || p.Metadata.Expiry.After(paths[prev].Metadata.Expiry) {
			uniquePaths[key] = i
		}
	}

	toKeep := make([]int, 0, len(uniquePaths))
	for _, idx := range uniquePaths {
		toKeep = append(toKeep, idx)
	}
	sort.Ints(toKeep)
	filtered := make([]Path, 0, len(toKeep))
	for _, i := range toKeep {
		filtered = append(filtered, paths[i])
	}
	return filtered
}

// fingerprint uniquely identifies the path based on the sequence of
// ASes and BRs, i.e. by its PathInterfaces.
// XXX(matzf): copied from snet.Fingerprint. Perhaps snet.Fingerprint could be adapted to
// take []snet.PathInterface directly.
func fingerprint(interfaces []snet.PathInterface) snet.PathFingerprint {
	h := sha256.New()
	for _, intf := range interfaces {
		if err := binary.Write(h, binary.BigEndian, intf.IA); err != nil {
			panic(err)
		}
		if err := binary.Write(h, binary.BigEndian, intf.ID); err != nil {
			panic(err)
		}
	}
	return snet.PathFingerprint(h.Sum(nil))
}
