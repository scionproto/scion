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

package segutil_test

import (
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/cs/segutil"
	"github.com/scionproto/scion/go/cs/segutil/mock_segutil"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestFilter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := graph.NewDefaultGraph(ctrl)
	seg110To120 := g.Beacon([]common.IFIDType{graph.If_110_X_120_A}, false)
	seg110To130 := g.Beacon([]common.IFIDType{graph.If_110_X_130_A}, false)

	tests := map[string]struct {
		Segs         seg.Segments
		Dir          segutil.Direction
		Policy       func(ctrl *gomock.Controller) segutil.Policy
		ExpectedSegs seg.Segments
	}{
		"filter all": {
			Segs: seg.Segments{seg110To120, seg110To130},
			Policy: func(ctrl *gomock.Controller) segutil.Policy {
				pol := mock_segutil.NewMockPolicy(ctrl)
				pol.EXPECT().FilterOpt(gomock.Any(), pathpol.FilterOptions{IgnoreSequence: true})
				return pol
			},
			ExpectedSegs: seg.Segments{},
		},
		"filter 120": {
			Segs: seg.Segments{seg110To120, seg110To130},
			Policy: func(ctrl *gomock.Controller) segutil.Policy {
				pol := mock_segutil.NewMockPolicy(ctrl)
				pol.EXPECT().FilterOpt(gomock.Any(), pathpol.FilterOptions{IgnoreSequence: true}).
					DoAndReturn(func(paths pathpol.PathSet,
						f pathpol.FilterOptions) pathpol.PathSet {
						for key := range paths {
							if strings.Contains(string(key), "120") {
								delete(paths, key)
							}
						}
						return paths
					})
				return pol
			},
			ExpectedSegs: seg.Segments{seg110To130},
		},
		"filter nothing": {
			Segs: seg.Segments{seg110To120, seg110To130},
			Policy: func(ctrl *gomock.Controller) segutil.Policy {
				pol := mock_segutil.NewMockPolicy(ctrl)
				pol.EXPECT().FilterOpt(gomock.Any(), pathpol.FilterOptions{IgnoreSequence: true}).
					DoAndReturn(func(paths pathpol.PathSet,
						f pathpol.FilterOptions) pathpol.PathSet {

						return paths
					})
				return pol
			},
			ExpectedSegs: seg.Segments{seg110To120, seg110To130},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			assert.ElementsMatch(t, test.ExpectedSegs,
				segutil.Filter(test.Segs, test.Policy(ctrl), test.Dir))
		})
	}
}
