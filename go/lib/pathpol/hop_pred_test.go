// Copyright 2018 ETH Zurich
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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
)

func TestNewHopPredicate(t *testing.T) {
	testCases := []struct {
		Name  string
		In    string
		HP    *HopPredicate
		Valid bool
	}{
		{
			Name:  "ISD wildcard",
			In:    "0",
			HP:    &HopPredicate{ISD: 0, AS: 0, IfIDs: []common.IFIDType{0}},
			Valid: true,
		},
		{
			Name:  "AS, IF wildcard omitted",
			In:    "1",
			HP:    &HopPredicate{ISD: 1, AS: 0, IfIDs: []common.IFIDType{0}},
			Valid: true,
		},
		{
			Name:  "IF wildcard omitted",
			In:    "1-0",
			HP:    &HopPredicate{ISD: 1, AS: 0, IfIDs: []common.IFIDType{0}},
			Valid: true,
		},
		{
			Name:  "basic wildcard",
			In:    "1-0#0",
			HP:    &HopPredicate{ISD: 1, AS: 0, IfIDs: []common.IFIDType{0}},
			Valid: true,
		},
		{
			Name:  "AS wildcard, interface set",
			In:    "1-0#1",
			Valid: false,
		},
		{
			Name:  "ISD wildcard, AS set",
			In:    "0-1#0",
			HP:    &HopPredicate{ISD: 0, AS: 1, IfIDs: []common.IFIDType{0}},
			Valid: true,
		},
		{
			Name:  "ISD wildcard, AS set, interface set",
			In:    "0-1#2",
			HP:    &HopPredicate{ISD: 0, AS: 1, IfIDs: []common.IFIDType{2}},
			Valid: true,
		},
		{
			Name:  "ISD wildcard, AS set and interface omitted",
			In:    "0-1",
			HP:    &HopPredicate{ISD: 0, AS: 1, IfIDs: []common.IFIDType{0}},
			Valid: true,
		},
		{
			Name:  "IF wildcard omitted, AS set",
			In:    "1-2",
			HP:    &HopPredicate{ISD: 1, AS: 2, IfIDs: []common.IFIDType{0}},
			Valid: true,
		},
		{
			Name:  "two IfIDs",
			In:    "1-2#3,4",
			HP:    &HopPredicate{ISD: 1, AS: 2, IfIDs: []common.IFIDType{3, 4}},
			Valid: true,
		},
		{
			Name:  "three IfIDs",
			In:    "1-2#3,4,5",
			Valid: false,
		},
		{
			Name:  "bad -",
			In:    "1-1-0",
			Valid: false,
		},
		{
			Name:  "missing AS",
			In:    "1#2",
			Valid: false,
		},
		{
			Name:  "bad #",
			In:    "1-1#0#",
			Valid: false,
		},
		{
			Name:  "bad IF",
			In:    "1-1#e",
			Valid: false,
		},
		{
			Name:  "bad second IF",
			In:    "1-2#1,3a",
			Valid: false,
		},
		{
			Name:  "AS wildcard, second IF defined",
			In:    "1-0#1,3",
			Valid: false,
		},
		{
			Name:  "bad AS",
			In:    "1-12323433243534#0",
			Valid: false,
		},
		{
			Name:  "bad ISD",
			In:    "1123212-23#0",
			Valid: false,
		},
	}

	Convey("TestNewHopPredicate", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				hp, err := HopPredicateFromString(tc.In)
				if tc.Valid {
					SoMsg("err", err, ShouldBeNil)
					SoMsg("hp", hp, ShouldResemble, tc.HP)
				} else {
					SoMsg("err", err, ShouldNotBeNil)
				}
			})
		}
	})
}

func TestHopPredicateString(t *testing.T) {
	Convey("TestString", t, func() {
		hp, _ := HopPredicateFromString("1-2#3,4")
		SoMsg("hp", hp.String(), ShouldEqual, "1-2#3,4")
	})
}

func TestJsonConversion(t *testing.T) {
	testCases := []struct {
		Name string
		HP   *HopPredicate
	}{
		{
			Name: "Normal predicate",
			HP:   &HopPredicate{ISD: 1, AS: 2, IfIDs: []common.IFIDType{1, 2}},
		},
		{
			Name: "wildcard predicate",
			HP:   &HopPredicate{ISD: 1, AS: 2, IfIDs: []common.IFIDType{0}},
		},
		{
			Name: "only ifids",
			HP:   &HopPredicate{IfIDs: []common.IFIDType{0}},
		},
	}
	Convey("TestJsonConversion", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				jsonHP, err := json.Marshal(tc.HP)
				SoMsg("err", err, ShouldBeNil)

				var hp HopPredicate
				err = json.Unmarshal(jsonHP, &hp)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("predicate", tc.HP, ShouldResemble, &hp)
			})
		}
	})
}
