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
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	update = flag.Bool("update", false, "set to true to update reference testdata files")
)

func TestClassMap(t *testing.T) {
	testCases := []struct {
		Name     string
		FileName string
		Classes  ClassMap
	}{
		{
			Name:     "ABC",
			FileName: "class_1",
			Classes: ClassMap{
				"transit ISD 1": NewClass(
					"transit ISD 1",
					NewCondAllOf(
						NewCondIPv4(&IPv4MatchToS{0x80}),
						NewCondIPv4(&IPv4MatchDestination{
							&net.IPNet{
								IP:   net.IP{192, 168, 1, 0},
								Mask: net.IPv4Mask(255, 255, 255, 0),
							},
						}),
					),
				),
				"transit ISD 2": NewClass(
					"transit ISD 2",
					NewCondAnyOf(
						NewCondIPv4(&IPv4MatchToS{0x0}),
						NewCondIPv4(&IPv4MatchSource{
							&net.IPNet{
								IP:   net.IP{10, 0, 0, 0},
								Mask: net.IPv4Mask(255, 0, 0, 0),
							},
						}),
					),
				),
				"classC": NewClass(
					"classC",
					NewCondAllOf(),
				),
			},
		},
		{
			Name:     "nil ClassMap stays nil",
			FileName: "class_2",
			Classes:  nil,
		},
	}

	Convey("Test class marshal/unmarshal", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				if *update {
					xtest.MustMarshalJSONToFile(t, tc.Classes, tc.FileName+".json")
				}

				expected, err := ioutil.ReadFile(xtest.ExpandPath(tc.FileName + ".json"))
				xtest.FailOnErr(t, err)

				// Check that marshaling matches reference files
				enc, err := json.MarshalIndent(tc.Classes, "", "    ")
				SoMsg("err marshal", err, ShouldBeNil)
				SoMsg("bytes",
					string(enc),
					ShouldResemble,
					strings.TrimRight(string(expected), "\n"))

				// Check that unmarshaling from reference files matches structure
				var classes ClassMap
				err = json.Unmarshal(expected, &classes)
				SoMsg("err unmarshal", err, ShouldBeNil)
				SoMsg("object", classes, ShouldResemble, tc.Classes)
			})
		}
	})
}

func TestBadJSON(t *testing.T) {
	testCases := []string{`
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
	Convey("Marshaling bad JSON should return errors", t, func() {
		for i, tc := range testCases {
			var c Class
			err := json.Unmarshal([]byte(tc), &c)
			SoMsg(fmt.Sprintf("err %d", i), err, ShouldNotBeNil)
		}
	})
}
