// Copyright 2017 ETH Zurich
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

package pktcls_test

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	update = flag.Bool("update", false, "set to true to update reference testdata files")
)

func TestClassMapMarshalUnMarshal(t *testing.T) {
	testCases := []struct {
		Name     string
		FileName string
		Classes  pktcls.ClassMap
	}{
		{
			Name:     "ABC",
			FileName: "class_1",
			Classes: pktcls.ClassMap{
				"transit ISD 1": pktcls.NewClass(
					"transit ISD 1",
					pktcls.NewCondAllOf(
						pktcls.NewCondIPv4(&pktcls.IPv4MatchToS{TOS: 0x80}),
						pktcls.NewCondIPv4(&pktcls.IPv4MatchDestination{
							Net: &net.IPNet{
								IP:   net.IP{192, 168, 1, 0},
								Mask: net.IPv4Mask(255, 255, 255, 0),
							},
						}),
					),
				),
				"transit ISD 2": pktcls.NewClass(
					"transit ISD 2",
					pktcls.NewCondAnyOf(
						pktcls.NewCondIPv4(&pktcls.IPv4MatchToS{TOS: 0x0}),
						pktcls.NewCondIPv4(&pktcls.IPv4MatchProtocol{Protocol: 6}),
						pktcls.NewCondIPv4(&pktcls.IPv4MatchSource{
							Net: &net.IPNet{
								IP:   net.IP{10, 0, 0, 0},
								Mask: net.IPv4Mask(255, 0, 0, 0),
							},
						}),
						pktcls.NewCondPorts(&pktcls.PortMatchSource{MinPort: 1, MaxPort: 10}),
					),
				),
				"classC": pktcls.NewClass(
					"classC",
					pktcls.NewCondAllOf(),
				),
			},
		},
		{
			Name:     "nil ClassMap stays nil",
			FileName: "class_2",
			Classes:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			if *update {
				xtest.MustMarshalJSONToFile(t, tc.Classes, tc.FileName+".json")
			}

			expected, err := ioutil.ReadFile(xtest.ExpandPath(tc.FileName + ".json"))
			require.NoError(t, err)

			// Check that marshaling matches reference files
			enc, err := json.MarshalIndent(tc.Classes, "", "    ")
			require.NoError(t, err)
			assert.Equal(t, strings.TrimRight(string(expected), "\n"), string(enc))

			// Check that unmarshaling from reference files matches structure
			var classes pktcls.ClassMap
			err = json.Unmarshal(expected, &classes)
			require.NoError(t, err)
			assert.Equal(t, tc.Classes, classes)
		})
	}
}

func TestClassUnmarshalError(t *testing.T) {
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
		{
			"CondIPv4": {
				"MatchProtocol": {
					"Protocol": "foo"
				}
			},
			"Name": "Unable to parse source operand string"
		}
	`}
	for i, tc := range testCases {
		var c pktcls.Class
		err := json.Unmarshal([]byte(tc), &c)
		assert.Error(t, err, "err %d", i)
	}
}
