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

package pktcls

import (
	"encoding/json"
	"strconv"

	"github.com/scionproto/scion/go/lib/common"
)

type Typer interface {
	Type() string
}

// This package makes extensive use of serialized interfaces. This requires
// special handling during marshaling and unmarshaling to take concrete types
// into account. During marshaling, an object of type T that implements some
// interface I is encoded as {"T": JSON(I)}, where JSON(I) is the normal
// encoding of type T.
//
// Marshaling uses a custom map with a single entry with key a string "T" and
// value interface{} containing the object iself.
//
// Unmarshaling uses a custom map of type map[string]*json.RawMessage which
// delays the unmarshaling of the object itself. After unmarshaling to this
// map, it contains a single entry with key "T". Depending on T, the correct
// concrete type is unmarshaled.

const (
	TypeCondAllOf            = "CondAllOf"
	TypeCondAnyOf            = "CondAnyOf"
	TypeCondNot              = "CondNot"
	TypeCondBool             = "CondBool"
	TypeCondIPv4             = "CondIPv4"
	TypeIPv4MatchSource      = "MatchSource"
	TypeIPv4MatchDestination = "MatchDestination"
	TypeIPv4MatchToS         = "MatchToS"
	TypeIPv4MatchDSCP        = "MatchDSCP"
)

// generic container for marshaling custom data
type jsonContainer map[string]interface{}

func marshalInterface(t Typer) ([]byte, error) {
	return json.Marshal(jsonContainer{t.Type(): t})
}

// unmarshalInterface receives a JSON encoded object with a single field whose
// key is a type and value is the JSON encoding of an object of that type, and
// returns an interface containing that concrete type.
func unmarshalInterface(b []byte) (Typer, error) {
	var container map[string]*json.RawMessage
	err := json.Unmarshal(b, &container)
	if err != nil {
		return nil, err
	}
	for k, v := range container {
		switch k {
		case TypeCondAllOf:
			var c CondAllOf
			if v == nil {
				return c, nil
			}
			err := json.Unmarshal(*v, &c)
			return c, err
		case TypeCondAnyOf:
			var c CondAnyOf
			if v == nil {
				return c, nil
			}
			err := json.Unmarshal(*v, &c)
			return c, err
		case TypeCondNot:
			var c CondNot
			err := json.Unmarshal(*v, &c)
			return c, err
		case TypeCondBool:
			var c CondBool
			err := json.Unmarshal(*v, &c)
			return c, err
		case TypeCondIPv4:
			var c CondIPv4
			err := json.Unmarshal(*v, &c)
			return &c, err
		case TypeIPv4MatchSource:
			var p IPv4MatchSource
			err := json.Unmarshal(*v, &p)
			return &p, err
		case TypeIPv4MatchDestination:
			var p IPv4MatchDestination
			err := json.Unmarshal(*v, &p)
			return &p, err
		case TypeIPv4MatchToS:
			var p IPv4MatchToS
			err := json.Unmarshal(*v, &p)
			return &p, err
		case TypeIPv4MatchDSCP:
			var p IPv4MatchDSCP
			err := json.Unmarshal(*v, &p)
			return &p, err
		default:
			return nil, common.NewBasicError("Unknown type", nil, "type", k)
		}
	}
	return nil, nil
}

// unmarshalCond extracts a Cond from a JSON encoding
func unmarshalCond(b []byte) (Cond, error) {
	t, err := unmarshalInterface(b)
	if err != nil {
		return nil, err
	}
	c, ok := t.(Cond)
	if !ok {
		return nil, common.NewBasicError("Unable to extract Cond from interface", nil)
	}
	return c, nil
}

// unmarshalAction extracts an Action from a JSON encoding
func unmarshalAction(b []byte) (Action, error) {
	t, err := unmarshalInterface(b)
	if err != nil {
		return nil, err
	}
	a, ok := t.(Action)
	if !ok {
		return nil, common.NewBasicError("Unable to extract Cond from interface", nil)
	}
	return a, nil
}

// unmarshal extracts an IPv4Predicate from a JSON encoding
func unmarshalPredicate(b []byte) (IPv4Predicate, error) {
	t, err := unmarshalInterface(b)
	if err != nil {
		return nil, err
	}
	p, ok := t.(IPv4Predicate)
	if !ok {
		return nil, common.NewBasicError("Unable to extract Cond from interface", nil)
	}
	return p, nil
}

// Special case slices because we only need them for Conds

func marshalCondSlice(conds []Cond) ([]byte, error) {
	var jsons []*json.RawMessage
	for _, cond := range conds {
		b, err := marshalInterface(cond)
		if err != nil {
			return nil, err
		}
		jsons = append(jsons, (*json.RawMessage)(&b))
	}
	return json.Marshal(jsons)
}

func unmarshalCondSlice(b []byte) ([]Cond, error) {
	var jsons []*json.RawMessage
	err := json.Unmarshal(b, &jsons)
	if err != nil {
		return nil, err
	}
	var conds []Cond
	for _, v := range jsons {
		cond, err := unmarshalCond(*v)
		if err != nil {
			return nil, err
		}
		conds = append(conds, cond)
	}
	return conds, nil
}

func unmarshalStringField(b []byte, name, field string) (string, error) {
	var jc jsonContainer
	err := json.Unmarshal(b, &jc)
	if err != nil {
		return "", err
	}
	v, ok := jc[field]
	if !ok {
		return "", common.NewBasicError("String field missing", nil, "name", name, "field", field)
	}
	s, ok := v.(string)
	if !ok {
		return "", common.NewBasicError("Field is non-string", nil,
			"name", name, "field", field, "type", common.TypeOf(v))
	}
	return s, nil
}

func unmarshalUintField(b []byte, name, field string, width int) (uint64, error) {
	s, err := unmarshalStringField(b, name, field)
	if err != nil {
		return 0, err
	}
	i, err := strconv.ParseUint(s, 0, width)
	if err != nil {
		return 0, common.NewBasicError("Unable to parse uint field", err,
			"name", name, "field", field)
	}
	return i, nil
}
