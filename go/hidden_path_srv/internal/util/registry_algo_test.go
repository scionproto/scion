// Copyright 2019 ETH Zurich
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

package util_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/util"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/hiddenpath/hiddenpathtest"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	regLocal = xtest.MustParseIA("1-ff00:0:0")
	reg1     = xtest.MustParseIA("1-ff00:0:1")
	reg2     = xtest.MustParseIA("1-ff00:0:2")
	reg3     = xtest.MustParseIA("1-ff00:0:3")
	id1      = hiddenpathtest.MustParseHPGroupId("ff00:0:0-1")
	id2      = hiddenpathtest.MustParseHPGroupId("ff00:0:0-2")
	id3      = hiddenpathtest.MustParseHPGroupId("ff00:0:0-3")
	id4      = hiddenpathtest.MustParseHPGroupId("ff00:0:0-4")
)

var g1 = &hiddenpath.Group{
	Id: id1,
}

var g2 = &hiddenpath.Group{
	Id: id2,
}

var g3 = &hiddenpath.Group{
	Id: id3,
}

func TestCases(t *testing.T) {
	var testcases = []map[hiddenpath.GroupId][]addr.IA{
		{
			// one remote Registry covers all Ids but needs splitting because of local rule
			id1: {reg1},
			id2: {reg1},
			id3: {reg1},
			id4: {reg1, regLocal},
		},
		{
			// all Ids covered by one remote Registry
			id1: {reg1},
			id2: {reg1},
			id3: {reg1},
		},
		{
			// all Ids covered by local Registry
			id1: {regLocal},
			id2: {regLocal},
			id3: {regLocal},
		},
		{
			// all Ids covered by a different Registry
			id1: {reg1},
			id2: {reg2},
			id3: {reg3},
		},
		{
			// Not all Registries needed
			id1: {reg1},
			id2: {reg1, reg2},
			id3: {reg3},
		},
	}

	for _, testcase := range testcases {
		set := buildSet(t, testcase)
		mapping, err := util.GetRegistryMapping(set, regLocal)
		require.NoError(t, err)

		t.Run("All Registries are valid", func(t *testing.T) {
			allRegs := []addr.IA{}
			for _, v := range set {
				allRegs = append(allRegs, v.Registries...)
			}
			computed := make([]addr.IA, 0, len(allRegs))
			for r := range mapping {
				computed = append(computed, r)
			}
			require.Subset(t, allRegs, computed)
		})

		t.Run("All GroupIds are covered exactly once", func(t *testing.T) {
			expected := make([]hiddenpath.GroupId, 0, len(set))
			for _, v := range set {
				expected = append(expected, v.Id)
			}
			computed := make([]hiddenpath.GroupId, 0, len(set))
			for _, v := range mapping {
				computed = append(computed, v...)
			}
			assert.ElementsMatch(t, expected, computed)
		})

		t.Run("Local Ids are covered by local HPS", func(t *testing.T) {
			localGroups := make([]hiddenpath.GroupId, 0, len(set))
			for _, g := range set {
				if g.HasRegistry(regLocal) {
					localGroups = append(localGroups, g.Id)
				}
			}
			assert.ElementsMatch(t, localGroups, mapping[regLocal])
		})

		t.Run("Registry can answer request", func(t *testing.T) {
			for r, ids := range mapping {
				for _, id := range ids {
					for _, e := range set {
						if e.Id == id {
							assert.True(t, e.HasRegistry(r))
						}
					}
				}
			}
		})
	}

	t.Run("Test duplicates", func(t *testing.T) {
		var testcase = map[hiddenpath.GroupId][]addr.IA{
			id1: {reg1},
		}
		set := buildSet(t, testcase)
		set = append(set, set[0])
		_, err := util.GetRegistryMapping(set, regLocal)
		assert.EqualError(t, err, "Provided Groups contain duplicates group=\"{ff00:0:0 1}\"")
	})

	t.Run("Test no Registries", func(t *testing.T) {
		var testcase = map[hiddenpath.GroupId][]addr.IA{
			id1: {},
		}
		set := buildSet(t, testcase)
		_, err := util.GetRegistryMapping(set, regLocal)
		assert.EqualError(t, err, "Group does not have any Registries group=\"{ff00:0:0 1}\"")
	})

}

func Benchmark(b *testing.B) {
	groups := make([]*hiddenpath.Group, 0, 100)
	for i := 0; i < 100; i++ {
		id := hiddenpathtest.MustParseHPGroupId(fmt.Sprintf("0:0:0-%d", i))
		g := &hiddenpath.Group{
			Id: id,
		}
		for j := 100 * i; j < 100*(i+1); j++ {
			ia := xtest.MustParseIA(fmt.Sprintf("1-ff00:0:%d", j))
			g.Registries = append(g.Registries, ia)
		}
		groups = append(groups, g)
	}
	for n := 0; n < b.N; n++ {
		util.GetRegistryMapping(groups, addr.IA{})
	}
}

func buildSet(t *testing.T, rule map[hiddenpath.GroupId][]addr.IA) []*hiddenpath.Group {
	groups := make([]*hiddenpath.Group, 0, len(rule))
	for id, regs := range rule {
		g := &hiddenpath.Group{Id: id}
		for _, reg := range regs {
			g.Registries = append(g.Registries, reg)
		}
		groups = append(groups, g)
	}
	return groups
}
