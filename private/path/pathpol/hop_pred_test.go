// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/segment/iface"
)

func TestNewHopPredicate(t *testing.T) {
	tests := map[string]struct {
		In    string
		HP    *HopPredicate
		Valid bool
	}{
		"ISD wildcard": {
			In:    "0",
			HP:    &HopPredicate{ISD: 0, AS: 0, IfIDs: []iface.ID{0}},
			Valid: true,
		},
		"AS, IF wildcard omitted": {
			In:    "1",
			HP:    &HopPredicate{ISD: 1, AS: 0, IfIDs: []iface.ID{0}},
			Valid: true,
		},
		"IF wildcard omitted": {
			In:    "1-0",
			HP:    &HopPredicate{ISD: 1, AS: 0, IfIDs: []iface.ID{0}},
			Valid: true,
		},
		"basic wildcard": {
			In:    "1-0#0",
			HP:    &HopPredicate{ISD: 1, AS: 0, IfIDs: []iface.ID{0}},
			Valid: true,
		},
		"AS wildcard, interface set": {
			In:    "1-0#1",
			Valid: false,
		},
		"ISD wildcard, AS set": {
			In:    "0-1#0",
			HP:    &HopPredicate{ISD: 0, AS: 1, IfIDs: []iface.ID{0}},
			Valid: true,
		},
		"ISD wildcard, AS set, interface set": {
			In:    "0-1#2",
			HP:    &HopPredicate{ISD: 0, AS: 1, IfIDs: []iface.ID{2}},
			Valid: true,
		},
		"ISD wildcard, AS set and interface omitted": {
			In:    "0-1",
			HP:    &HopPredicate{ISD: 0, AS: 1, IfIDs: []iface.ID{0}},
			Valid: true,
		},
		"IF wildcard omitted, AS set": {
			In:    "1-2",
			HP:    &HopPredicate{ISD: 1, AS: 2, IfIDs: []iface.ID{0}},
			Valid: true,
		},
		"two IfIDs": {
			In:    "1-2#3,4",
			HP:    &HopPredicate{ISD: 1, AS: 2, IfIDs: []iface.ID{3, 4}},
			Valid: true,
		},
		"three IfIDs": {
			In:    "1-2#3,4,5",
			Valid: false,
		},
		"bad -": {
			In:    "1-1-0",
			Valid: false,
		},
		"missing AS": {
			In:    "1#2",
			Valid: false,
		},
		"bad #": {
			In:    "1-1#0#",
			Valid: false,
		},
		"bad IF": {
			In:    "1-1#e",
			Valid: false,
		},
		"bad second IF": {
			In:    "1-2#1,3a",
			Valid: false,
		},
		"AS wildcard, second IF defined": {
			In:    "1-0#1,3",
			Valid: false,
		},
		"bad AS": {
			In:    "1-12323433243534#0",
			Valid: false,
		},
		"bad ISD": {
			In:    "1123212-23#0",
			Valid: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			hp, err := HopPredicateFromString(test.In)
			if test.Valid {
				assert.NoError(t, err)
				assert.Equal(t, test.HP, hp)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestHopPredicateString(t *testing.T) {
	hp, _ := HopPredicateFromString("1-2#3,4")
	assert.Equal(t, "1-2#3,4", hp.String())
}

func TestJsonConversion(t *testing.T) {
	tests := map[string]struct {
		Name string
		HP   *HopPredicate
	}{
		"Normal predicate": {
			HP: &HopPredicate{ISD: 1, AS: 2, IfIDs: []iface.ID{1, 2}},
		},
		"wildcard predicate": {
			HP: &HopPredicate{ISD: 1, AS: 2, IfIDs: []iface.ID{0}},
		},
		"only ifIDs": {
			HP: &HopPredicate{IfIDs: []iface.ID{0}},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			jsonHP, err := json.Marshal(test.HP)
			if assert.NoError(t, err) {
				var hp HopPredicate
				err = json.Unmarshal(jsonHP, &hp)
				assert.NoError(t, err)
				assert.Equal(t, test.HP, &hp)
			}
		})
	}
}
