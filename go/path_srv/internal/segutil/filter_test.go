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

package segutil

import (
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestFilter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := graph.NewDefaultGraph(ctrl)
	ia110 := xtest.MustParseIA("1-ff00:0:110")
	ia111 := xtest.MustParseIA("1-ff00:0:111")
	ia120 := xtest.MustParseIA("1-ff00:0:120")
	seg110To120 := g.Beacon([]common.IFIDType{graph.If_110_X_120_A})
	seg110To130 := g.Beacon([]common.IFIDType{graph.If_110_X_130_A})

	// TODO delete method IsPartial
	tests := map[string]struct {
		Segs         seg.Segments
		Dir          Direction
		Policy       *pathpol.Policy
		ExpectedSegs seg.Segments
	}{
		"no policy": {
			Segs:         seg.Segments{seg110To120, seg110To130},
			ExpectedSegs: seg.Segments{seg110To120, seg110To130},
		},
		"acl policy": {
			Segs:         seg.Segments{seg110To120, seg110To130},
			Policy:       &pathpol.Policy{ACL: acl(t, ia120)},
			ExpectedSegs: seg.Segments{seg110To130},
		},
		"sequence policy doesn't filter": {
			Segs:         seg.Segments{seg110To120, seg110To130},
			Policy:       &pathpol.Policy{Sequence: sequence(t, ia111, ia110)},
			ExpectedSegs: seg.Segments{seg110To120, seg110To130},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.ExpectedSegs, Filter(test.Segs, test.Policy, test.Dir))
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

func sequence(t testing.TB, ias ...addr.IA) *pathpol.Sequence {
	parts := make([]string, 0, len(ias))
	for _, ia := range ias {
		parts = append(parts, ia.String())
	}
	seq, err := pathpol.NewSequence(strings.Join(parts, " "))
	require.NoError(t, err)
	return seq
}
