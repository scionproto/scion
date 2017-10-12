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
	"fmt"
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestClassMap(t *testing.T) {
	Convey("Create class map", t, func() {
		cm := NewClassMap()
		Convey("Add element classA", func() {
			classA := NewClass("classA", nil)
			err := cm.Add(classA)
			SoMsg("err", err, ShouldBeNil)

			Convey("Retrieve classA should return the class", func() {
				class, err := cm.Get("classA")
				SoMsg("err", err, ShouldBeNil)
				SoMsg("class", class, ShouldResemble, classA)
			})

			Convey("Retrieve classB should return error", func() {
				_, err := cm.Get("classB")
				SoMsg("err", err, ShouldNotBeNil)
			})

			Convey("Add classA again should return error", func() {
				err := cm.Add(NewClass("classA", nil))
				SoMsg("err", err, ShouldNotBeNil)
			})

			Convey("Remove classB should return error", func() {
				err := cm.Remove("classB")
				SoMsg("err", err, ShouldNotBeNil)
			})

			Convey("Remove classA should work", func() {
				err := cm.Remove("classA")
				SoMsg("err", err, ShouldBeNil)
			})
		})
	})
}

func TestMarshalClassMap(t *testing.T) {
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
