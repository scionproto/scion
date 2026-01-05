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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/pathdb/query"
)

var _ gomock.Matcher = (*addrIAMatcher)(nil)

type addrIAMatcher struct {
	ia addr.IA
}

// IsSnetSVCAddrWithIA returns a matcher for a snet.SVCAddr with the given IA.
func IsSnetSVCAddrWithIA(ia addr.IA) gomock.Matcher {
	return &addrIAMatcher{ia: ia}
}

func (m *addrIAMatcher) Matches(x any) bool {
	sAddr, ok := x.(*snet.SVCAddr)
	if !ok {
		return false
	}
	return sAddr.IA.Equal(m.ia)
}

func (m *addrIAMatcher) String() string {
	return fmt.Sprintf("Matching addr with IA %v", m.ia)
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
func (m *QueryParams) Matches(x any) bool {
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
	sort.Slice(query.HPGroupIDs, func(i, j int) bool {
		return (query.HPGroupIDs[i] < query.HPGroupIDs[j])
	})
	sort.Slice(query.Intfs, func(i, j int) bool {
		return (query.Intfs[i].IA < query.Intfs[j].IA) ||
			(query.Intfs[i].IA == query.Intfs[j].IA &&
				query.Intfs[i].IfID < query.Intfs[j].IfID)
	})
	sort.Slice(query.StartsAt, func(i, j int) bool {
		return query.StartsAt[i] < query.StartsAt[j]
	})
	sort.Slice(query.EndsAt, func(i, j int) bool {
		return query.EndsAt[i] < query.EndsAt[j]
	})
	return reflect.DeepEqual(m.query, query)
}

func (m *QueryParams) String() string {
	return fmt.Sprintf("is query.Params = %v", m.query)
}

// EqHPGroupIDs returns a matcher for the given slice of HPGroupIDs.
func EqHPGroupIDs(ids []uint64) *QueryHPGroupIDs {
	return &QueryHPGroupIDs{ids: ids}
}

// QueryHPGroupIDs is a matcher for HPGroupIDs.
type QueryHPGroupIDs struct {
	ids []uint64
}

// Matches returns whether x matches the defined HPGroupIDs ignoring the
// order of the slice elements.
func (m *QueryHPGroupIDs) Matches(x any) bool {
	ids, ok := x.([]uint64)
	if !ok {
		return false
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})
	return reflect.DeepEqual(m.ids, ids)
}

func (m *QueryHPGroupIDs) String() string {
	return fmt.Sprintf("is []uint64 = %v", m.ids)
}

// PartialStruct can be used to match a struct partially. All specified fields
// in the target struct will be matched. The field values which have a zero
// value are ignored. Passing a target which is not a struct or a pointer to a
// struct is invalid and will result in a matcher that matches nothing.
type PartialStruct struct {
	Target any
}

func (m PartialStruct) Matches(x any) bool {
	expect := reflect.ValueOf(m.Target)
	unpack := func(v reflect.Value) reflect.Value { return v }
	if expect.Kind() == reflect.Ptr {
		unpack = func(v reflect.Value) reflect.Value { return v.Elem() }
		expect = expect.Elem()
	}
	if expect.Kind() != reflect.Struct {
		return false
	}
	if reflect.TypeOf(m.Target) != reflect.TypeOf(x) {
		return false
	}
	v := unpack(reflect.ValueOf(x))
	for i := 0; i < expect.NumField(); i++ {
		ev := expect.Field(i)
		if ev.IsZero() {
			continue
		}
		av := v.Field(i)
		if !reflect.DeepEqual(ev.Interface(), av.Interface()) {
			return false
		}
	}
	return true
}

func (m PartialStruct) String() string {
	return fmt.Sprintf("partial struct with non-zero fields: %s", m.Target)
}
