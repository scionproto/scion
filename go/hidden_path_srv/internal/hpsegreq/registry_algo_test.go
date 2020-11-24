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

package hpsegreq_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpath"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpath/hiddenpathtest"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hpsegreq"
	"github.com/scionproto/scion/go/lib/addr"
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

type testcase struct {
	groups map[hiddenpath.GroupId][]addr.IA
	ids    []hiddenpath.GroupId
}

func TestCases(t *testing.T) {
	var tests = map[string]testcase{
		"one remote Registry covers all Ids but needs splitting because of local rule": {
			groups: map[hiddenpath.GroupId][]addr.IA{
				id1: {reg1},
				id2: {reg1},
				id3: {reg1, regLocal},
			},
			ids: []hiddenpath.GroupId{
				id1, id2, id3,
			},
		},
		"all Ids covered by one remote Registry": {
			groups: map[hiddenpath.GroupId][]addr.IA{
				id1: {reg1},
				id2: {reg1},
				id3: {reg1},
			},
			ids: []hiddenpath.GroupId{
				id1, id2, id3,
			},
		},
		"all Ids covered by local Registry": {
			groups: map[hiddenpath.GroupId][]addr.IA{
				id1: {regLocal},
				id2: {regLocal},
				id3: {regLocal},
			},
			ids: []hiddenpath.GroupId{
				id1, id2, id3,
			},
		},
		"all Ids covered by a different Registry": {
			groups: map[hiddenpath.GroupId][]addr.IA{
				id1: {reg1},
				id2: {reg2},
				id3: {reg3},
			},
			ids: []hiddenpath.GroupId{
				id1, id2, id3,
			},
		},
		"not all Registries needed": {
			groups: map[hiddenpath.GroupId][]addr.IA{
				id1: {reg1},
				id2: {reg1, reg2},
				id3: {reg3},
			},
			ids: []hiddenpath.GroupId{
				id1, id2, id3,
			},
		},
		"query subset of ids only": {
			groups: map[hiddenpath.GroupId][]addr.IA{
				id1: {reg1},
				id2: {reg1, reg2},
				id3: {reg3},
			},
			ids: []hiddenpath.GroupId{
				id1,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			info := &hpsegreq.GroupInfo{}
			info.LocalIA = regLocal
			info.Groups = buildGroups(t, test.groups)
			mapping, err := info.GetRegistryMapping(hiddenpath.GroupIdsToSet(test.ids...))
			require.NoError(t, err)

			testRegistriesValid(t, info, mapping)
			testIdsCoveredExactlyOnce(t, info, test.ids, mapping)
			testLocalIdsCoveredByLocalReg(t, info, test.ids, mapping)
			testRegCanAnswerRequest(t, info, mapping)
		})
	}
}

func TestUnknownIds(t *testing.T) {
	info := &hpsegreq.GroupInfo{}
	ids := []hiddenpath.GroupId{id1}
	_, err := info.GetRegistryMapping(hiddenpath.GroupIdsToSet(ids...))
	assert.EqualError(t, err, `Unknown group group="ff00:0:0-1"`)
}

func TestDuplicateIds(t *testing.T) {
	var testcase = map[hiddenpath.GroupId][]addr.IA{
		id1: {reg1},
	}
	info := &hpsegreq.GroupInfo{}
	info.Groups = buildGroups(t, testcase)
	ids := []hiddenpath.GroupId{id1, id1}
	_, err := info.GetRegistryMapping(hiddenpath.GroupIdsToSet(ids...))
	assert.NoError(t, err)
}

func TestNoRegistries(t *testing.T) {
	var testcase = map[hiddenpath.GroupId][]addr.IA{
		id1: {},
	}
	info := &hpsegreq.GroupInfo{}
	info.Groups = buildGroups(t, testcase)
	ids := []hiddenpath.GroupId{id1}
	_, err := info.GetRegistryMapping(hiddenpath.GroupIdsToSet(ids...))
	assert.EqualError(t, err, `Group does not have any Registries group="ff00:0:0-1"`)
}

func testRegistriesValid(t *testing.T, info *hpsegreq.GroupInfo,
	mapping map[addr.IA][]hiddenpath.GroupId) {

	allRegs := []addr.IA{}
	for _, g := range info.Groups {
		allRegs = append(allRegs, g.Registries...)
	}
	actualRegs := make([]addr.IA, 0, len(allRegs))
	for r := range mapping {
		actualRegs = append(actualRegs, r)
	}
	require.Subset(t, allRegs, actualRegs, "returned Registries invalid")
}

func testIdsCoveredExactlyOnce(t *testing.T, info *hpsegreq.GroupInfo,
	expected []hiddenpath.GroupId, mapping map[addr.IA][]hiddenpath.GroupId) {

	actual := make([]hiddenpath.GroupId, 0, len(info.Groups))
	for _, v := range mapping {
		actual = append(actual, v...)
	}
	assert.ElementsMatch(t, expected, actual, "GroupId must appear exactly once")
}

func testLocalIdsCoveredByLocalReg(t *testing.T, info *hpsegreq.GroupInfo,
	ids []hiddenpath.GroupId, mapping map[addr.IA][]hiddenpath.GroupId) {

	localGroups := make([]hiddenpath.GroupId, 0, len(info.Groups))
	for _, id := range ids {
		if info.Groups[id].HasRegistry(regLocal) {
			localGroups = append(localGroups, id)
		}
	}
	assert.ElementsMatch(t, localGroups, mapping[regLocal], "Local Registry must be proritized")
}

func testRegCanAnswerRequest(t *testing.T, info *hpsegreq.GroupInfo,
	mapping map[addr.IA][]hiddenpath.GroupId) {

	for r, ids := range mapping {
		for _, id := range ids {
			assert.True(t, info.Groups[id].HasRegistry(r),
				"Registry must be responsible for given GroupId")
		}
	}
}

func buildGroups(t *testing.T,
	rule map[hiddenpath.GroupId][]addr.IA) map[hiddenpath.GroupId]*hiddenpath.Group {

	groups := make(map[hiddenpath.GroupId]*hiddenpath.Group, len(rule))
	for id, regs := range rule {
		g := &hiddenpath.Group{Id: id}
		for _, reg := range regs {
			g.Registries = append(g.Registries, reg)
		}
		groups[id] = g
	}
	return groups
}
