// Copyright 2017 ETH Zurich
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

package class

import "github.com/netsec-ethz/scion/go/lib/common"

// When condUnion is unmarshaled, only the field corresponding to the correct type
// is populated.
type condUnion struct {
	CondAllOf *CondAll
	CondAnyOf *CondAny
	CondIPv4  *CondIPv4
	CondBool  *CondBool
}

// ExtractI returns an interface value containing the populated field in s.
func (u *condUnion) extractCond() (Cond, error) {
	if u.CondAllOf != nil {
		// Dereference to retrieve reference
		return *u.CondAllOf, nil
	}
	if u.CondAnyOf != nil {
		// Dereference to retrieve reference
		return *u.CondAnyOf, nil
	}
	if u.CondIPv4 != nil {
		// Return pointer directly
		return u.CondIPv4, nil
	}
	if u.CondBool != nil {
		// Dereference to retrieve bool
		return *u.CondBool, nil
	}
	return nil, common.NewCError("No valid condition found")
}

type actionUnion struct {
	ActionFilterPaths *ActionFilterPaths
}

func (u *actionUnion) extractAction(name string) (Action, error) {
	if u.ActionFilterPaths != nil {
		u.ActionFilterPaths.Name = name
		return u.ActionFilterPaths, nil
	}
	return nil, common.NewCError("No valid action found")
}

type predicateUnion struct {
	MatchTOS         *MatchTOS
	MatchDestination *MatchDestination
	MatchSource      *MatchSource
}

func (u *predicateUnion) extractPredicate() IPv4Predicate {
	if u.MatchTOS != nil {
		return u.MatchTOS
	}
	if u.MatchDestination != nil {
		return u.MatchDestination
	}
	if u.MatchSource != nil {
		return u.MatchSource
	}
	return nil
}
