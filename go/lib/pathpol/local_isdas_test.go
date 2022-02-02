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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestLocalISDASEval(t *testing.T) {
	tests := map[string]struct {
		AllowedIAs []addr.IA
		ExpPathNum int
	}{
		"first isdas": {
			AllowedIAs: xtest.MustParseIAs("2-ff00:0:212"),
			ExpPathNum: 6,
		},
		"second isdas": {
			AllowedIAs: xtest.MustParseIAs("2-ff00:0:220"),
			ExpPathNum: 6,
		},
		"both isdases": {
			AllowedIAs: xtest.MustParseIAs("2-ff00:0:212,2-ff00:0:220"),
			ExpPathNum: 12,
		},
		"extra isdas": {
			AllowedIAs: xtest.MustParseIAs("2-ff00:0:212,2-ff00:0:220,1-ff00:0:220"),
			ExpPathNum: 12,
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	paths212 := pp.GetPaths(xtest.MustParseIA("2-ff00:0:212"), xtest.MustParseIA("2-ff00:0:220"))
	paths220 := pp.GetPaths(xtest.MustParseIA("2-ff00:0:220"), xtest.MustParseIA("2-ff00:0:212"))
	inPaths := append(paths212, paths220...)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			li := LocalISDAS{AllowedIAs: test.AllowedIAs}
			outPaths := li.Eval(inPaths)
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}
