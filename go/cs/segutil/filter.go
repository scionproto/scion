// Copyright 2019 Anapaya Systems
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

package segutil

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/snet"
)

type Direction int

const (
	ReverseConsDir Direction = iota
	ConsDir
)

// Policy filters path sets according to a set of rules.
type Policy interface {
	FilterOpt(pathpol.PathSet, pathpol.FilterOptions) pathpol.PathSet
}

// Filter filters the given segments with the policy. Dir indicates the
// direction of intended usage of the segments. For example up and core segments
// are most often used in reverse construction dir. The direction parameter is
// relevant for the sequence matching of policies. Note that order of segs is
// not preserved.
// NOTE: This function should only be applied on core segments, otherwise the PS
// might filter segments that could still have been used in a final path,
// because of peering links.
// NOTE: policy must not be nil.
func Filter(segs seg.Segments, policy Policy, dir Direction) seg.Segments {
	// The sequence filter doesn't work for segments, therefore the option to
	// ignore sequences is passed.
	return psToSegs(policy.FilterOpt(segsToPs(segs, dir), pathpol.FilterOptions{
		IgnoreSequence: true,
	}))
}

func segsToPs(segs seg.Segments, dir Direction) pathpol.PathSet {
	ps := make(pathpol.PathSet, len(segs))
	for _, seg := range segs {
		sw := wrap(seg, dir)
		ps[sw.Fingerprint()] = sw
	}
	return ps
}

func psToSegs(ps pathpol.PathSet) seg.Segments {
	segs := make(seg.Segments, 0, len(ps))
	for _, sw := range ps {
		seg := sw.(segWrap).origSeg
		segs = append(segs, seg)
	}
	return segs
}

type segWrap struct {
	intfs   []snet.PathInterface
	key     snet.PathFingerprint
	origSeg *seg.PathSegment
}

func wrap(seg *seg.PathSegment, dir Direction) segWrap {
	intfs := make([]snet.PathInterface, 0, len(seg.ASEntries))
	keyParts := make([]string, 0, len(seg.ASEntries))
	for _, asEntry := range seg.ASEntries {
		for _, hopEntry := range asEntry.HopEntries {
			hopField := hopEntry.HopField
			for _, ifid := range []uint16{hopField.ConsIngress, hopField.ConsEgress} {
				if ifid != 0 {
					intfs = append(intfs, pathInterface{
						ia:   asEntry.IA(),
						ifid: common.IFIDType(ifid),
					})
					keyParts = append(keyParts, fmt.Sprintf("%s#%d", asEntry.IA(), ifid))
				}
			}
		}
	}
	if dir == ReverseConsDir {
		// reverse interfaces
		for left, right := 0, len(intfs)-1; left < right; left, right = left+1, right-1 {
			intfs[left], intfs[right] = intfs[right], intfs[left]
		}
	}
	return segWrap{
		intfs:   intfs,
		key:     snet.PathFingerprint(strings.Join(keyParts, " ")),
		origSeg: seg,
	}
}

func (s segWrap) Interfaces() []snet.PathInterface  { return s.intfs }
func (s segWrap) Fingerprint() snet.PathFingerprint { return s.key }

type pathInterface struct {
	ia   addr.IA
	ifid common.IFIDType
}

func (i pathInterface) IA() addr.IA         { return i.ia }
func (i pathInterface) ID() common.IFIDType { return i.ifid }
