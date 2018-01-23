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

package pathmgr

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

var ppPaths = map[string]*sciond.PathReplyEntry{
	"1-19->2-25": {
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{RawIsdas: IA("1-19"), IfID: 60}, {RawIsdas: IA("1-16"), IfID: 38},
				{RawIsdas: IA("1-16"), IfID: 22}, {RawIsdas: IA("1-13"), IfID: 23},
				{RawIsdas: IA("1-13"), IfID: 46}, {RawIsdas: IA("1-11"), IfID: 18},
				{RawIsdas: IA("1-11"), IfID: 87}, {RawIsdas: IA("2-21"), IfID: 97},
				{RawIsdas: IA("2-21"), IfID: 69}, {RawIsdas: IA("2-23"), IfID: 57},
				{RawIsdas: IA("2-23"), IfID: 66}, {RawIsdas: IA("2-25"), IfID: 74},
			},
		},
	},
	"1-10->1-18": {
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{RawIsdas: IA("1-10"), IfID: 51}, {RawIsdas: IA("1-19"), IfID: 49},
				{RawIsdas: IA("1-19"), IfID: 60}, {RawIsdas: IA("1-16"), IfID: 38},
				{RawIsdas: IA("1-16"), IfID: 30}, {RawIsdas: IA("1-15"), IfID: 35},
				{RawIsdas: IA("1-15"), IfID: 84}, {RawIsdas: IA("1-18"), IfID: 40},
			},
		},
	},
	"2-26->1-17": {
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{RawIsdas: IA("2-26"), IfID: 75}, {RawIsdas: IA("2-22"), IfID: 77},
				{RawIsdas: IA("2-22"), IfID: 49}, {RawIsdas: IA("1-12"), IfID: 23},
				{RawIsdas: IA("1-12"), IfID: 95}, {RawIsdas: IA("1-11"), IfID: 54},
				{RawIsdas: IA("1-11"), IfID: 28}, {RawIsdas: IA("1-14"), IfID: 48},
				{RawIsdas: IA("1-14"), IfID: 49}, {RawIsdas: IA("1-17"), IfID: 14},
			},
		},
	},
	"2-22->1-16": {
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{RawIsdas: IA("2-22"), IfID: 49}, {RawIsdas: IA("1-12"), IfID: 23},
				{RawIsdas: IA("1-12"), IfID: 66}, {RawIsdas: IA("1-13"), IfID: 85},
				{RawIsdas: IA("1-13"), IfID: 23}, {RawIsdas: IA("1-16"), IfID: 22},
			},
		},
	},
	"1-18->2-25": {
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{RawIsdas: IA("1-18"), IfID: 40}, {RawIsdas: IA("1-15"), IfID: 84},
				{RawIsdas: IA("1-15"), IfID: 64}, {RawIsdas: IA("1-12"), IfID: 35},
				{RawIsdas: IA("1-12"), IfID: 23}, {RawIsdas: IA("2-22"), IfID: 49},
				{RawIsdas: IA("2-22"), IfID: 10}, {RawIsdas: IA("2-21"), IfID: 22},
				{RawIsdas: IA("2-21"), IfID: 69}, {RawIsdas: IA("2-23"), IfID: 57},
				{RawIsdas: IA("2-23"), IfID: 66}, {RawIsdas: IA("2-25"), IfID: 74},
			},
		},
	},
	"2-21->2-26": {
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{RawIsdas: IA("2-21"), IfID: 69}, {RawIsdas: IA("2-23"), IfID: 57},
				{RawIsdas: IA("2-23"), IfID: 17}, {RawIsdas: IA("2-26"), IfID: 34},
			},
		},
	},
	"1-11->2-23": {
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{RawIsdas: IA("1-11"), IfID: 87}, {RawIsdas: IA("2-21"), IfID: 97},
				{RawIsdas: IA("2-21"), IfID: 69}, {RawIsdas: IA("2-23"), IfID: 57},
			},
		},
	},
	"1-13->1-18": {
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{RawIsdas: IA("1-13"), IfID: 46}, {RawIsdas: IA("1-11"), IfID: 18},
				{RawIsdas: IA("1-11"), IfID: 54}, {RawIsdas: IA("1-12"), IfID: 95},
				{RawIsdas: IA("1-12"), IfID: 35}, {RawIsdas: IA("1-15"), IfID: 64},
				{RawIsdas: IA("1-15"), IfID: 84}, {RawIsdas: IA("1-18"), IfID: 40},
			},
		},
	},
}

func TestPathPredicates(t *testing.T) {
	testCases := []struct {
		predicateStr string
		appPathStr   string
		expected     bool
	}{
		{"2-26#75", "2-26->1-17", true},
		{"2-26#75", "1-19->2-25", false},
		{"1-18#0", "1-10->1-18", true},
		{"1-15#0", "2-22->1-16", false},
		{"2-0#0", "1-11->2-23", true},
		{"2-0#0", "1-13->1-18", false},
		{"1-12#95,1-11#54", "2-26->1-17", true},
		{"1-0#0,1-0#0", "1-11->2-23", false},
		{"2-21#69,2-23#57,2-23#17,2-26#34", "2-21->2-26", true},
		{"2-0#0,2-0#0,2-23#17,2-26#0", "2-21->2-26", true},
	}

	Convey("Test for various predicates and paths", t, func() {
		for _, tc := range testCases {
			Convey(fmt.Sprintf("Predicate=%s, Path=%s\n", tc.predicateStr, tc.appPathStr), func() {
				pp, err := NewPathPredicate(tc.predicateStr)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("pp", pp, ShouldNotBeNil)
				match := pp.Eval(ppPaths[tc.appPathStr])
				SoMsg("match", match, ShouldEqual, tc.expected)
			})
		}
	})
}

func TestPathPredicateString(t *testing.T) {
	testCases := []struct {
		expr string
	}{
		{"1-10#42"},
		{"1-10#42,1-10#43"},
		{"1-10#0,1-10#0"},
		{"1-0#0"},
		{"2-0#0,2-0#0,3-0#0,3-0#0,4-41#1041,4-41#1051"},
	}
	Convey("Compile path predicates", t, func() {
		for _, tc := range testCases {
			Convey(fmt.Sprintf("expr=%s", tc.expr), func() {
				ppA, err := NewPathPredicate(tc.expr)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("string", ppA.String(), ShouldEqual, tc.expr)
			})
		}
	})
}

func IA(iaStr string) addr.IAInt {
	ia, _ := addr.IAFromString(iaStr)
	return ia.IAInt()
}
