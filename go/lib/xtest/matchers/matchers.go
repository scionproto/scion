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

// File matchers contains matchers for gomock.

package matchers

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ gomock.Matcher = (*addrIAMatcher)(nil)

type addrIAMatcher struct {
	ia addr.IA
}

// IsSnetSVCAddrWithIA returns a matcher for a snet.SVCAddr with the given IA.
func IsSnetSVCAddrWithIA(ia addr.IA) gomock.Matcher {
	return &addrIAMatcher{ia: ia}
}

func (m *addrIAMatcher) Matches(x interface{}) bool {
	sAddr, ok := x.(*snet.SVCAddr)
	if !ok {
		return false
	}
	return sAddr.IA.Equal(m.ia)
}

func (m *addrIAMatcher) String() string {
	return fmt.Sprintf("Matching addr with IA %v", m.ia)
}

var _ gomock.Matcher = (*SignedRevs)(nil)

// SignedRevs matches signed revocations against revinfos and checks if they
// are verifiable.
type SignedRevs struct {
	Verifier  path_mgmt.Verifier
	MatchRevs []path_mgmt.RevInfo
}

// Matches returns whether the matcher matches x.
func (m *SignedRevs) Matches(x interface{}) bool {
	sRevs, ok := x.([]*path_mgmt.SignedRevInfo)
	if !ok {
		return false
	}
	revInfos := make(map[path_mgmt.RevInfo]*path_mgmt.RevInfo)
	for _, rev := range sRevs {
		revInfo, err := rev.RevInfo()
		if err != nil {
			return false
		}
		key := *revInfo
		key.RawTimestamp, key.RawTTL = 0, 0
		revInfos[key] = revInfo
	}
	for _, expectedRev := range m.MatchRevs {
		expectedRev.RawTimestamp, expectedRev.RawTTL = 0, 0
		rev, ok := revInfos[expectedRev]
		if !ok {
			return false
		}
		if rev.Active() != nil {
			return false
		}
		delete(revInfos, expectedRev)
	}
	return len(revInfos) == 0
}

func (m *SignedRevs) String() string {
	return fmt.Sprintf("is slice of signed revocations matching %v and verifiable", m.MatchRevs)
}

// EqParams returns a matcher for the given query parameters.
func EqParams(query *query.Params) *QueryParams {
	return &QueryParams{query: query}
}

// QueryParams is a matcher for query parameters.
type QueryParams struct {
	query *query.Params
}

// Matches returns whether x matches the defined query parameter ignoring the
// order of the slices.
func (m *QueryParams) Matches(x interface{}) bool {
	query, ok := x.(*query.Params)
	if !ok {
		return false
	}
	sort.Slice(query.SegIDs, func(i, j int) bool {
		return bytes.Compare(query.SegIDs[i], query.SegIDs[j]) < 0
	})
	sort.Slice(query.SegTypes, func(i, j int) bool {
		return query.SegTypes[i] < query.SegTypes[j]
	})
	sort.Slice(query.HpCfgIDs, func(i, j int) bool {
		return (query.HpCfgIDs[i].IA.IAInt() < query.HpCfgIDs[j].IA.IAInt()) ||
			(query.HpCfgIDs[i].IA.IAInt() == query.HpCfgIDs[j].IA.IAInt() &&
				query.HpCfgIDs[i].ID < query.HpCfgIDs[j].ID)
	})
	sort.Slice(query.Intfs, func(i, j int) bool {
		return (query.Intfs[i].IA.IAInt() < query.Intfs[j].IA.IAInt()) ||
			(query.Intfs[i].IA.IAInt() == query.Intfs[j].IA.IAInt() &&
				query.Intfs[i].IfID < query.Intfs[j].IfID)
	})
	sort.Slice(query.StartsAt, func(i, j int) bool {
		return query.StartsAt[i].IAInt() < query.StartsAt[j].IAInt()
	})
	sort.Slice(query.EndsAt, func(i, j int) bool {
		return query.EndsAt[i].IAInt() < query.EndsAt[j].IAInt()
	})
	return reflect.DeepEqual(m.query, query)
}

func (m *QueryParams) String() string {
	return fmt.Sprintf("is query.Params = %v", m.query)
}

// EqHPCfgIDs returns a matcher for the given slice of HPCfgIDs.
func EqHPCfgIDs(ids []*query.HPCfgID) *QueryHPCfgIDs {
	return &QueryHPCfgIDs{ids: ids}
}

// QueryHPCfgIDs is a matcher for HPCfgIDs.
type QueryHPCfgIDs struct {
	ids []*query.HPCfgID
}

// Matches returns whether x matches the defined HPCfgIDs ignoring the
// order of the slice elements.
func (m *QueryHPCfgIDs) Matches(x interface{}) bool {
	ids, ok := x.([]*query.HPCfgID)
	if !ok {
		return false
	}
	sort.Slice(ids, func(i, j int) bool {
		return (ids[i].IA.IAInt() < ids[j].IA.IAInt()) ||
			(ids[i].IA.IAInt() == ids[j].IA.IAInt() &&
				ids[i].ID < ids[j].ID)
	})
	return reflect.DeepEqual(m.ids, ids)
}

func (m *QueryHPCfgIDs) String() string {
	return fmt.Sprintf("is []*query.HPCfgID = %v", m.ids)
}
