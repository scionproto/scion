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

package segment

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers/path"
)

var (
	core1_110 = addr.MustParseIA("1-ff00:0:110")
	core1_120 = addr.MustParseIA("1-ff00:0:120")
)

func allocPathSegment(ias []addr.IA) *PathSegment {
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
					ExpTime:     63,
					MAC:         [path.MacLen]byte{0xab, 0xab, 0xab, 0xab, 0xab, 0xab},
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
	seg110_120 := allocPathSegment([]addr.IA{core1_110, core1_120})
	seg120_110 := allocPathSegment([]addr.IA{core1_120, core1_110})

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
			_, err := segs.FilterSegs(test.KeepF)
			assert.NoError(t, err)
			assert.Equal(t, Segments(test.Filtered), segs)
		})
	}
}
