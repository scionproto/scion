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

package fetcher

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestFilter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := graph.NewDefaultGraph(ctrl)
	ia110 := xtest.MustParseIA("1-ff00:0:110")
	ia120 := xtest.MustParseIA("1-ff00:0:120")
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
		Policy        func(t *testing.T) *pathpol.Policy
		ExpectedPaths []*combinator.Path
	}{
		"Test without policy": {
			Paths:         paths111To110,
			Policy:        func(t *testing.T) *pathpol.Policy { return nil },
			ExpectedPaths: paths111To110,
		},
		"Test with policy": {
			Paths: paths111To110,
			Policy: func(t *testing.T) *pathpol.Policy {
				return &pathpol.Policy{ACL: acl(t, ia120)}
			},
			ExpectedPaths: combinator.Combine(ia111, ia110,
				[]*seg.PathSegment{seg130To111},
				[]*seg.PathSegment{seg110To130},
				nil),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			filtered := Filter(test.Paths, test.Policy(t))
			assert.ElementsMatch(t, test.ExpectedPaths, filtered)
		})
	}
}

func acl(t testing.TB, disallow addr.IA) *pathpol.ACL {
	var disallowEntry pathpol.ACLEntry
	err := disallowEntry.LoadFromString(fmt.Sprintf("- %s", disallow))
	xtest.FailOnErr(t, err)
	var allowEntry pathpol.ACLEntry
	err = allowEntry.LoadFromString("+")
	xtest.FailOnErr(t, err)
	acl, err := pathpol.NewACL(&disallowEntry, &allowEntry)
	xtest.FailOnErr(t, err)
	return acl
}
