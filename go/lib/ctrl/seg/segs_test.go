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
	"bytes"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
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
	ases := make([]ASEntry, len(ias))
	for i := range ias {
		var next addr.IA
		if i < len(ias)-1 {
			next = ias[i+1]
		}
		ases[i] = ASEntry{
			Local: ias[i],
			Next:  next,
			MTU:   1337,
			HopEntry: HopEntry{
				HopField: HopField{
					ConsIngress: 1,
					ConsEgress:  2,
					ExpTime:     uint8(spath.DefaultHopFExpiry),
					MAC:         bytes.Repeat([]byte{0xab}, 6),
				},
				IngressMTU: 1337,
			},
		}
	}
	ps, err := CreateSegment(time.Now(), 1337)
	if err != nil {
		panic(err)
	}
	ps.ASEntries = ases
	return ps
}

func TestFilterSegments(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	seg110_120 := allocPathSegment(ctrl, []addr.IA{core1_110, core1_120})
	seg120_110 := allocPathSegment(ctrl, []addr.IA{core1_120, core1_110})

	tests := map[string]struct {
		Segs     []*PathSegment
		Filtered []*PathSegment
		KeepF    func(*PathSegment) (bool, error)
	}{
		"Keep all": {
			Segs:     []*PathSegment{seg110_120},
			Filtered: []*PathSegment{seg110_120},
			KeepF:    func(s *PathSegment) (bool, error) { return true, nil },
		},
		"Drop all": {
			Segs:     []*PathSegment{seg110_120},
			Filtered: []*PathSegment{},
			KeepF:    func(s *PathSegment) (bool, error) { return false, nil },
		},
		"First IA core 1_110": {
			Segs:     []*PathSegment{seg110_120, seg120_110},
			Filtered: []*PathSegment{seg120_110},
			KeepF: func(s *PathSegment) (bool, error) {
				return core1_120.Equal(s.FirstIA()), nil
			},
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
