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
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
)

func TestLocalISDASEval(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	paths212 := pp.GetPaths(addr.MustParseIA("2-ff00:0:212"), addr.MustParseIA("2-ff00:0:220"))
	paths220 := pp.GetPaths(addr.MustParseIA("2-ff00:0:220"), addr.MustParseIA("2-ff00:0:212"))
	inPaths := append(paths212, paths220...)
	localPath := mock_snet.NewMockPath(ctrl)
	localPath.EXPECT().Source().Return(addr.MustParseIA("2-ff00:0:220"))
	localPath.EXPECT().Destination().Return(addr.MustParseIA("2-ff00:0:220"))
	tests := map[string]struct {
		AllowedIAs []addr.IA
		ExpPathNum int
		Paths      []snet.Path
	}{
		"first isdas": {
			AllowedIAs: []addr.IA{addr.MustParseIA("2-ff00:0:212")},
			ExpPathNum: 6,
			Paths:      inPaths,
		},
		"second isdas": {
			AllowedIAs: []addr.IA{addr.MustParseIA("2-ff00:0:220")},
			ExpPathNum: 6,
			Paths:      inPaths,
		},
		"both isdases": {
			AllowedIAs: []addr.IA{
				addr.MustParseIA("2-ff00:0:212"),
				addr.MustParseIA("2-ff00:0:220"),
			},
			ExpPathNum: 12,
			Paths:      inPaths,
		},
		"extra isdas": {
			AllowedIAs: []addr.IA{
				addr.MustParseIA("2-ff00:0:212"),
				addr.MustParseIA("2-ff00:0:220"),
				addr.MustParseIA("1-ff00:0:220"),
			},
			ExpPathNum: 12,
			Paths:      inPaths,
		},
		"local paths are not counted": {
			AllowedIAs: []addr.IA{addr.MustParseIA("2-ff00:0:220")},
			ExpPathNum: 6,
			Paths:      append(inPaths, localPath),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			li := LocalISDAS{AllowedIAs: test.AllowedIAs}
			outPaths := li.Eval(test.Paths)
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}
