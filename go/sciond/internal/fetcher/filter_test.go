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

package fetcher_test

import (
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/sciond/internal/fetcher"
	"github.com/scionproto/scion/go/sciond/internal/fetcher/mock_fetcher"
)

func TestFilter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := graph.NewDefaultGraph(ctrl)
	ia110 := xtest.MustParseIA("1-ff00:0:110")
	ia111 := xtest.MustParseIA("1-ff00:0:111")
	seg110To120 := g.Beacon([]common.IFIDType{graph.If_110_X_120_A})
	seg110To130 := g.Beacon([]common.IFIDType{graph.If_110_X_130_A})
	seg120To111 := g.Beacon([]common.IFIDType{graph.If_120_X_111_B})
	seg130To111 := g.Beacon([]common.IFIDType{graph.If_130_B_111_A})

	paths111To110 := combinator.Combine(ia111, ia110,
		[]*seg.PathSegment{seg120To111, seg130To111},
		[]*seg.PathSegment{seg110To120, seg110To130},
		nil)

	tests := map[string]struct {
		Paths         []*combinator.Path
		Policy        func(ctrl *gomock.Controller) fetcher.Policy
		ExpectedPaths []*combinator.Path
	}{
		"Test with policy": {
			Paths: paths111To110,
			Policy: func(ctrl *gomock.Controller) fetcher.Policy {
				pol := mock_fetcher.NewMockPolicy(ctrl)
				pol.EXPECT().Filter(gomock.Any()).DoAndReturn(
					func(paths pathpol.PathSet) pathpol.PathSet {
						for key := range paths {
							if strings.Contains(string(key), "120") {
								delete(paths, key)
							}
						}
						return paths
					})
				return pol
			},
			ExpectedPaths: combinator.Combine(ia111, ia110,
				[]*seg.PathSegment{seg130To111},
				[]*seg.PathSegment{seg110To130},
				nil),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			filtered := fetcher.Filter(test.Paths, test.Policy(ctrl))
			assert.ElementsMatch(t, test.ExpectedPaths, filtered)
		})
	}
}
