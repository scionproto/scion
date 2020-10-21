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
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/spath"
)

// Combine constructs paths between src and dst using the supplied
// segments. All possible paths are first computed, and then filtered according
// to filterLongPaths. The remaining paths are returned sorted according to
// weight (on equal weight, see pathSolutionList.Less for the tie-breaking
// algorithm).
//
// If Combine cannot extract a hop field or info field from the segments, it
// panics.
func Combine(src, dst addr.IA, ups, cores, downs []*seg.PathSegment) []Path {
	solutions := newDMG(ups, cores, downs).GetPaths(vertexFromIA(src), vertexFromIA(dst))

	var pathSlice []Path
	for _, solution := range solutions {
		pathSlice = append(pathSlice, solution.Path())
	}
	return filterLongPaths(pathSlice)
}

type Path struct {
	Dst        addr.IA
	SPath      spath.Path
	Interfaces []snet.PathInterface
	Metadata   path.PathMetadata
	Weight     int // XXX(matzf): unused, drop this?
}

// filterLongPaths returns a new slice containing only those paths that do not
// go more than twice through interfaces belonging to the same AS (thus
// filtering paths containing useless loops).
func filterLongPaths(paths []Path) []Path {
	var newPaths []Path
	for _, path := range paths {
		long := false
		iaCounts := make(map[addr.IA]int)
		for _, iface := range path.Interfaces {
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
