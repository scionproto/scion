// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package pathpol

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
)

func TestNewSequence(t *testing.T) {
	tests := map[string]assert.ErrorAssertionFunc{
		"0-0-0#0": assert.Error,
		"0#0#0":   assert.Error,
		"0":       assert.NoError,
		"1#0":     assert.Error,
		"1-0":     assert.NoError,
	}
	for seq, assertion := range tests {
		t.Run(seq, func(t *testing.T) {
			_, err := NewSequence(seq)
			assertion(t, err, seq)
		})
	}
}

func TestSequenceEval(t *testing.T) {
	tests := map[string]struct {
		Seq        *Sequence
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		"Empty path": {
			Seq:        newSequence(t, "0-0#0"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 0,
		},
		"Asterisk matches empty path": {
			Seq:        newSequence(t, "0*"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 1,
		},
		"Asterisk on non-wildcard matches empty path": {
			Seq:        newSequence(t, "1-ff00:0:110#1,2*"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 1,
		},
		"Double Asterisk matches empty path": {
			Seq:        newSequence(t, "0* 0*"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 1,
		},
		"QuestionMark matches empty path": {
			Seq:        newSequence(t, "0*"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 1,
		},
		"Asterisk and QuestionMark matches empty path": {
			Seq:        newSequence(t, "0* 0?"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 1,
		},
		"Plus does not match empty path": {
			Seq:        newSequence(t, "0+"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 0,
		},
		"Length not matching": {
			Seq:        newSequence(t, "0-0#0"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		"Two Wildcard matching": {
			Seq:        newSequence(t, "0-0#0 0-0#0"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Longer Wildcard matching": {
			Seq:        newSequence(t, "0-0#0 0-0#0 0-0#0 0-0#0"),
			Src:        addr.MustParseIA("1-ff00:0:122"),
			Dst:        addr.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 2,
		},
		"Two Explicit matching": {
			Seq:        newSequence(t, "1-ff00:0:133#1019 1-ff00:0:132#1910"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:132"),
			ExpPathNum: 1,
		},
		"AS double IF matching": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1910,1916 0"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"AS IF matching, first wildcard": {
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1916 0"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching": {
			Seq: newSequence(t, "1-ff00:0:122#1815 1-ff00:0:121#1518,1530 "+
				"1-ff00:0:120#3015,3122 2-ff00:0:220#2231,2224 2-ff00:0:221#2422"),
			Src:        addr.MustParseIA("1-ff00:0:122"),
			Dst:        addr.MustParseIA("2-ff00:0:221"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, single wildcard": {
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#1810,1815 "+
				"1-ff00:0:121#0,1530 1-ff00:0:120#3015,2911 1-ff00:0:110#1129"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, reverse single wildcard": {
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#1810,1815 "+
				"1-ff00:0:121#1530,0 1-ff00:0:120#3015,2911 1-ff00:0:110#1129"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 0,
		},
		"Longer Explicit matching, multiple wildcard": {
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#0,1815 "+
				"1-ff00:0:121#0,1530 1-ff00:0:120#3015,0 1-ff00:0:110#1129"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, mixed wildcard types": {
			Seq: newSequence(t, "1-ff00:0:133#0 1 "+
				"0-0#0 1-ff00:0:120#0 1-ff00:0:110#1129"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, mixed wildcard types, two paths": {
			Seq: newSequence(t, "1-ff00:0:133#0 1-0#0 "+
				"0-0#0 1-0#0 1-ff00:0:110#0"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 2,
		},
		"Nil sequence does not filter": {
			Seq:        nil,
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Asterisk matches multiple hops": {
			Seq:        newSequence(t, "0*"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Asterisk matches zero hops": {
			Seq:        newSequence(t, "0 0 0*"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Plus matches multiple hops": {
			Seq:        newSequence(t, "0+"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Plus doesn't match zero hops": {
			Seq:        newSequence(t, "0 0 0+"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		"Question mark matches zero hops": {
			Seq:        newSequence(t, "0 0 0?"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Question mark matches one hop": {
			Seq:        newSequence(t, "0 0?"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Question mark doesn't match two hops": {
			Seq:        newSequence(t, "0?"),
			Src:        addr.MustParseIA("2-ff00:0:212"),
			Dst:        addr.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		"Successful match on hop count": {
			Seq:        newSequence(t, "0 0 0"),
			Src:        addr.MustParseIA("2-ff00:0:211"),
			Dst:        addr.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		"Failed match on hop count": {
			Seq:        newSequence(t, "0 0"),
			Src:        addr.MustParseIA("2-ff00:0:211"),
			Dst:        addr.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
		"Select one of the intermediate ASes": {
			Seq:        newSequence(t, "0 2-ff00:0:221 0"),
			Src:        addr.MustParseIA("2-ff00:0:211"),
			Dst:        addr.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		"Select two alternative intermediate ASes": {
			Seq:        newSequence(t, "0 (2-ff00:0:221 | 2-ff00:0:210) 0"),
			Src:        addr.MustParseIA("2-ff00:0:211"),
			Dst:        addr.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		"Alternative intermediate ASes, but one doesn't exist": {
			Seq:        newSequence(t, "0 (2-ff00:0:221 |64-12345) 0"),
			Src:        addr.MustParseIA("2-ff00:0:211"),
			Dst:        addr.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		"Or has higher priority than concatenation": {
			Seq:        newSequence(t, "0 2-ff00:0:221|64-12345 0"),
			Src:        addr.MustParseIA("2-ff00:0:211"),
			Dst:        addr.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		"Question mark has higher priority than concatenation": {
			Seq:        newSequence(t, "0 0 0 ?  "),
			Src:        addr.MustParseIA("2-ff00:0:211"),
			Dst:        addr.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		"Parentheses change priority": {
			Seq:        newSequence(t, "(0 0)?"),
			Src:        addr.MustParseIA("2-ff00:0:211"),
			Dst:        addr.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
		"Single interface matches inbound interface": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1910 0"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Single interface matches outbound interface": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1916 0"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Single non-matching interface": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1917 0"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
		"Left interface matches inbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1910,0 0"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Left interface doesn't match outbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1916,0 0"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
		"Right interface matches outbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1916 0"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Right interface doesn't match inbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1910 0"),
			Src:        addr.MustParseIA("1-ff00:0:133"),
			Dst:        addr.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			paths := pp.GetPaths(test.Src, test.Dst)
			outPaths := test.Seq.Eval(paths)
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}
