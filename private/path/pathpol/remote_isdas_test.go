// Copyright 2022 Anapaya Systems
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

func TestRemoteISDASEval(t *testing.T) {
	tests := map[string]struct {
		Rules      []ISDASRule
		ExpPathNum int
	}{
		"nil": {
			Rules:      nil,
			ExpPathNum: 0,
		},
		"reject all": {
			Rules:      []ISDASRule{},
			ExpPathNum: 0,
		},
		"accept all": {
			Rules: []ISDASRule{
				{IA: addr.MustParseIA("0-0")},
			},
			ExpPathNum: 6,
		},
		"as wildcard": {
			Rules: []ISDASRule{
				{IA: addr.MustParseIA("2-0")},
			},
			ExpPathNum: 5,
		},
		"isd wildcard": {
			Rules: []ISDASRule{
				{IA: addr.MustParseIA("0-ff00:0:212")},
			},
			ExpPathNum: 4,
		},
		"two rules": {
			Rules: []ISDASRule{
				{IA: addr.MustParseIA("1-0")},
				{IA: addr.MustParseIA("2-ff00:0:220")},
			},
			ExpPathNum: 2,
		},
		"two rules negated": {
			Rules: []ISDASRule{
				{IA: addr.MustParseIA("1-0"), Reject: true},
				{IA: addr.MustParseIA("0-0")},
			},
			ExpPathNum: 5,
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	paths1_110 := pp.GetPaths(addr.MustParseIA("2-ff00:0:210"), addr.MustParseIA("1-ff00:0:110"))
	paths2_212 := pp.GetPaths(addr.MustParseIA("2-ff00:0:210"), addr.MustParseIA("2-ff00:0:212"))
	paths2_220 := pp.GetPaths(addr.MustParseIA("2-ff00:0:210"), addr.MustParseIA("2-ff00:0:220"))
	inPaths := append(paths1_110, append(paths2_212, paths2_220...)...)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ri := RemoteISDAS{Rules: test.Rules}
			outPaths := ri.Eval(inPaths)
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}
