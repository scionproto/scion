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

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestMarshalJSONActions(t *testing.T) {
	Convey("Initialize path predicates", t, func() {
		ppA, err := NewPathPredicate("1-11#18,1-11#87")
		SoMsg("ppA err", err, ShouldBeNil)
		SoMsg("ppA", ppA, ShouldNotBeNil)
		ppB, err := NewPathPredicate("2-*#*")
		SoMsg("ppB err", err, ShouldBeNil)
		SoMsg("ppB", ppB, ShouldNotBeNil)
		Convey("Create action map", func() {
			actionMap := NewActionMap()
			actionMap.Add(NewActionFilterPaths("GoThrough1-11", ppA))
			actionMap.Add(NewActionFilterPaths("GoThrough2", ppB))
			Convey("Marshal JSON", func() {
				enc, err := json.MarshalIndent(actionMap, "", "    ")
				SoMsg("err", err, ShouldBeNil)
				Convey("Unmarshal back", func() {
					amu := NewActionMap()
					err := json.Unmarshal(enc, &amu)
					SoMsg("err", err, ShouldBeNil)
					Convey("Unmarshaled action-map should be the same as the initial one", func() {
						So(amu, ShouldResemble, actionMap)
					})
				})
			})
		})
	})
}

func TestMarshalJSONClass(t *testing.T) {
	Convey("Initialize traffic classes (conditions and actions)", t, func() {
		classA := NewClass(
			"Traffic class core ISD1",
			NewCondAllOf(
				CondTrue,
				NewCondAllOf(
					NewCondIPv4(&IPv4MatchToS{0x80}),
					NewCondIPv4(&IPv4MatchDestination{
						&net.IPNet{
							IP:   net.IP{192, 168, 1, 0},
							Mask: net.IPv4Mask(255, 255, 255, 0),
						}},
					),
				),
			),
		)
		classB := NewClass(
			"Traffic class transit ISD2",
			NewCondAnyOf(
				NewCondIPv4(&IPv4MatchToS{0x0}),
				NewCondIPv4(&IPv4MatchSource{
					&net.IPNet{
						IP:   net.IP{10, 0, 0, 0},
						Mask: net.IPv4Mask(255, 0, 0, 0),
					}},
				),
			),
		)
		classC := NewClass(
			"Traffic default",
			NewCondAllOf(),
		)

		cm := NewClassMap()
		cm.Add(classA)
		cm.Add(classB)
		cm.Add(classC)

		Convey("Marshal all classes to JSON", func() {
			enc, err := json.MarshalIndent(cm, "", "    ")
			SoMsg("Marshal err", err, ShouldBeNil)
			SoMsg("Marshal enc", enc, ShouldNotBeNil)
			Convey("Unmarshal back", func() {
				cmu := NewClassMap()
				err = json.Unmarshal(enc, &cmu)
				SoMsg("Unmarshal err", err, ShouldBeNil)
				Convey("Unmarshaled class-map should be the same as the initial one", func() {
					So(cmu, ShouldResemble, cm)
				})
			})
		})

	})
}

var badJSONs []string = []string{`
{
	"Name": "Undefined condition"
}
`, `
{
	"CondFoo": true,
	"Name": "Nonexistent cond type"
}
`, `
{
	"CondBool": "hello gophers",
	"Name": "Unparsable bool conditions"
}
`, `
{
	"CondAllOf": [
		{
			"CondBool": true
		},
		{
			"CondBool": "gopher"
		}
	],
	"Name": "Unparsable subcondition"
}
`, `
{
	"CondIPv4": {
		"x" "x"
	},
	"Name": "Bad JSON"
}
`, `
{
	"CondIPv4": {
		"MatchTOS": {
			"foo": 123
		}
	},
	"Name": "No TOS operand"
}
`, `
{
	"CondIPv4": {
		"MatchTOS": {
			"TOS": 17
		}
	},
	"Name": "Unable to parse ToS operand"
}
`, `
{
	"CondIPv4": {
		"MatchTOS": {
			"TOS": "0xx123"
		}
	},
	"Name": "Unable to parse ToS operand string"
}
`, `
{
	"CondIPv4": {
		"MatchDestination": {
			"foo": 123
		}
	},
	"Name": "No destination operand"
}
`, `
{
	"CondIPv4": {
		"MatchDestination": {
			"Net": 1234
		}
	},
	"Name": "Unable to parse destination operand"
}
`, `
{
	"CondIPv4": {
		"MatchDestination": {
			"Net": "1.2.3.4///"
		}
	},
	"Name": "Unable to parse destination operand string"
}
`, `
{
	"CondIPv4": {
		"MatchSource": {
			"foo": 123
		}
	},
	"Name": "No source operand"
}
`, `
{
	"CondIPv4": {
		"MatchSource": {
			"Net": 1234
		}
	},
	"Name": "Unable to parse source operand"
}
`, `
{
	"CondIPv4": {
		"MatchSource": {
			"Net": "1.2.3.4///"
		}
	},
	"Name": "Unable to parse source operand string"
}

`}

func TestBadJSON(t *testing.T) {
	Convey("Marshaling bad JSON should return errors", t, func() {
		for i, str := range badJSONs {
			Convey(fmt.Sprintf("Input %d", i+1), func() {
				var c Class
				err := json.Unmarshal([]byte(str), &c)
				SoMsg("err", err, ShouldNotBeNil)
			})
		}
	})
}
