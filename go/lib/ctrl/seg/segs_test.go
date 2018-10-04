// Copyright 2018 Anapaya Systems
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
	"fmt"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var (
	core1_110 = xtest.MustParseIA("1-ff00:0:110")
	core1_120 = xtest.MustParseIA("1-ff00:0:120")

	seg110_120 = allocPathSegment([]addr.IA{core1_110, core1_120})
	seg120_110 = allocPathSegment([]addr.IA{core1_120, core1_110})
)

func allocPathSegment(ias []addr.IA) *PathSegment {
	rawHops := make([][]byte, len(ias))
	for i := 0; i < len(ias); i++ {
		rawHops[i] = make([]byte, 8)
		spath.NewHopField(rawHops[i], common.IFIDType(1), common.IFIDType(2),
			spath.DefaultHopFExpiry)
	}
	ases := make([]*ASEntry, len(ias))
	for i := range ias {
		ia := ias[i]
		inIA := addr.IA{}
		if i > 0 {
			inIA = ias[i-1]
		}
		outIA := ia
		if i == len(ases)-1 {
			outIA = addr.IA{}
		}
		ases[i] = &ASEntry{
			RawIA:      ia.IAInt(),
			HopEntries: []*HopEntry{allocHopEntry(inIA, outIA, rawHops[i])},
		}
	}
	info := &spath.InfoField{
		TsInt: uint32(time.Now().Unix()),
		ISD:   uint16(ias[0].I),
	}
	pseg, _ := NewSeg(info)
	for _, ase := range ases {
		if err := pseg.AddASEntry(ase, proto.SignType_none, nil); err != nil {
			fmt.Printf("Error adding ASEntry: %v", err)
		}
	}
	return pseg
}

func allocHopEntry(inIA, outIA addr.IA, hopF common.RawBytes) *HopEntry {
	return &HopEntry{
		RawInIA:     inIA.IAInt(),
		RawOutIA:    outIA.IAInt(),
		RawHopField: hopF,
	}
}

func Test_FilterSegments(t *testing.T) {
	testCases := []struct {
		Name     string
		Segs     []*PathSegment
		Filtered []*PathSegment
		KeepF    func(*PathSegment) bool
	}{
		{
			Name:     "Keep all",
			Segs:     []*PathSegment{seg110_120},
			Filtered: []*PathSegment{seg110_120},
			KeepF:    func(s *PathSegment) bool { return true },
		},
		{
			Name:     "Drop all",
			Segs:     []*PathSegment{seg110_120},
			Filtered: []*PathSegment{},
			KeepF:    func(s *PathSegment) bool { return false },
		},
		{
			Name:     "First IA core 1_110",
			Segs:     []*PathSegment{seg110_120, seg120_110},
			Filtered: []*PathSegment{seg120_110},
			KeepF:    func(s *PathSegment) bool { return core1_120.Eq(s.FirstIA()) },
		},
	}
	Convey("Test filtering segments", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				segs := Segments(tc.Segs)
				segs.FilterSegs(tc.KeepF)
				SoMsg("Filtering not exact", segs, ShouldResemble, Segments(tc.Filtered))
			})
		}
	})
}
