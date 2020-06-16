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
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg/mock_seg"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var (
	core1_110 = xtest.MustParseIA("1-ff00:0:110")
	core1_120 = xtest.MustParseIA("1-ff00:0:120")
)

func allocPathSegment(ctrl *gomock.Controller, ias []addr.IA) *PathSegment {
	rawHops := make([][]byte, len(ias))
	for i := 0; i < len(ias); i++ {
		rawHops[i] = make([]byte, 8)
		hf := spath.HopField{
			ConsIngress: common.IFIDType(1),
			ConsEgress:  common.IFIDType(2),
			ExpTime:     spath.DefaultHopFExpiry,
		}
		hf.Write(rawHops[i])
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
	rawInfo := make([]byte, spath.InfoFieldLength)
	(&spath.InfoField{ISD: uint16(ias[0].I), TsInt: uint32(time.Now().Unix())}).Write(rawInfo)
	pseg, _ := NewSeg(&PathSegmentSignedData{
		RawInfo:      make([]byte, spath.InfoFieldLength),
		RawTimestamp: uint32(time.Now().Unix()),
		SegID:        1337,
	})
	signer := mock_seg.NewMockSigner(ctrl)
	signer.EXPECT().Sign(gomock.Any(), gomock.AssignableToTypeOf(common.RawBytes{})).Return(
		&proto.SignS{}, nil).AnyTimes()
	for _, ase := range ases {
		if err := pseg.AddASEntry(context.Background(), ase, signer); err != nil {
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

func TestFilterSegments(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	seg110_120 := allocPathSegment(ctrl, []addr.IA{core1_110, core1_120})
	seg120_110 := allocPathSegment(ctrl, []addr.IA{core1_120, core1_110})

	tests := map[string]struct {
		Segs     []*PathSegment
		Filtered []*PathSegment
		KeepF    func(*PathSegment) bool
	}{
		"Keep all": {
			Segs:     []*PathSegment{seg110_120},
			Filtered: []*PathSegment{seg110_120},
			KeepF:    func(s *PathSegment) bool { return true },
		},
		"Drop all": {
			Segs:     []*PathSegment{seg110_120},
			Filtered: []*PathSegment{},
			KeepF:    func(s *PathSegment) bool { return false },
		},
		"First IA core 1_110": {
			Segs:     []*PathSegment{seg110_120, seg120_110},
			Filtered: []*PathSegment{seg120_110},
			KeepF:    func(s *PathSegment) bool { return core1_120.Equal(s.FirstIA()) },
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			segs := Segments(test.Segs)
			segs.FilterSegs(test.KeepF)
			assert.Equal(t, Segments(test.Filtered), segs)
		})
	}
}
