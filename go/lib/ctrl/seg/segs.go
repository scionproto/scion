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

package seg

import (
	"github.com/scionproto/scion/go/lib/addr"
)

// Segments is just a helper type to have additional methods on top of a slice of PathSegments.
type Segments []*PathSegment

// FilterSegs filters the given segs and only keeps the segments for which keep returns true.
// Modifies segs in-place. Returns the number of segments filtered out.
func (segs *Segments) FilterSegs(keep func(*PathSegment) bool) int {
	mod, _ := segs.FilterSegsErr(func(ps *PathSegment) (bool, error) { return keep(ps), nil })
	return mod
}

// FilterSegsErr filters the given segs and only keeps the segments for which keep returns true.
// Modifies segs in-place. Returns the number of segments filtered out.
// If keep returns an error the method is aborted and the error is returned,
// segs might have been modified.
func (segs *Segments) FilterSegsErr(keep func(*PathSegment) (bool, error)) (int, error) {
	full := len(*segs)
	filtered := (*segs)[:0]
	for _, s := range *segs {
		if k, err := keep(s); err != nil {
			return 0, err
		} else if k {
			filtered = append(filtered, s)
		}
	}
	*segs = filtered
	return full - len(*segs), nil
}

// FirstIAs returns the slice of FirstIAs in the given segments. Each FirstIA appears just once.
func (segs Segments) FirstIAs() []addr.IA {
	return extractIAs(segs, (*PathSegment).FirstIA)
}

// LastIAs returns the slice of LastIAs in the given segments. Each LastIA appears just once.
func (segs Segments) LastIAs() []addr.IA {
	return extractIAs(segs, (*PathSegment).LastIA)
}

func extractIAs(segs []*PathSegment, extract func(*PathSegment) addr.IA) []addr.IA {
	var ias []addr.IA
	addrs := make(map[addr.IA]struct{})
	for _, s := range segs {
		ia := extract(s)
		if _, ok := addrs[ia]; !ok {
			addrs[ia] = struct{}{}
			ias = append(ias, ia)
		}
	}
	return ias
}
