// Copyright 2018 Anapaya Systems
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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/pktcls"
)

func TestTrafficClassValidation(t *testing.T) {
	testCases := []struct {
		Name  string
		Class string
		Valid bool
	}{
		{
			Name:  "src IPv4Cond",
			Class: "src=12.12.12.0/26",
			Valid: true,
		},
		{
			Name:  "dst IPv4Cond",
			Class: "dst=12.12.12.0/26",
			Valid: true,
		},
		{
			Name:  "bad dst IPv4Cond",
			Class: "dst=12.12.12.0",
			Valid: false,
		},
		{
			Name:  "dscp IPv4Cond",
			Class: "dscp=0x2",
			Valid: true,
		},
		{
			Name:  "bad dscp IPv4Cond",
			Class: "dscp=2",
			Valid: false,
		},
		{
			Name:  "NOT",
			Class: "NOT(dscp=0x2)",
			Valid: true,
		},
		{
			Name:  "bad NOT",
			Class: "Not(dscp=0x2)",
			Valid: false,
		},
		{
			Name:  "bad NOT ,",
			Class: "Not(dscp=0x2,)",
			Valid: false,
		},
		{
			Name:  "protocol IPv4Cond",
			Class: "protocol=tcp",
			Valid: true,
		},
		{
			Name:  "protocol IPv4Cond invalid",
			Class: "protocol=FOO",
			Valid: false,
		},
		{
			Name:  "BOOL",
			Class: "BOOL=true",
			Valid: true,
		},
		{
			Name:  "bad BOOL",
			Class: "BOOL=True",
			Valid: false,
		},
		{
			Name:  "single ALL",
			Class: "ALL(dscp=0x2)",
			Valid: true,
		},
		{
			Name:  "double ALL",
			Class: "ALL(dscp=0x2,dst=12.12.12.0/24)",
			Valid: true,
		},
		{
			Name:  "single ANY",
			Class: "ANY(dscp=0x2)",
			Valid: true,
		},
		{
			Name:  "double ANY",
			Class: "ANY(dscp=0x2,dst=12.12.12.0/24)",
			Valid: true,
		},
		{
			Name:  "bad triple ANY",
			Class: "ANY(dscp=0x2,dst=12.12.12.0/24,)",
			Valid: false,
		},
		{
			Name:  "ANY ALL NOT src dst dscp",
			Class: "ANY(dscp=0x2,ALL(dst=12.12.12.0/24,dscp=0x2, NOT(src=2.2.2.0/28)))",
			Valid: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			err := pktcls.ValidateTrafficClass(tc.Class)
			if tc.Valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestTrafficClassTree(t *testing.T) {
	_, net, _ := net.ParseCIDR("12.12.12.0/26")
	testCases := []struct {
		Name  string
		Class string
		Tree  pktcls.Cond
	}{
		{
			Name:  "src IPv4Cond",
			Class: "src=12.12.12.0/26",
			Tree: pktcls.NewCondIPv4(
				&pktcls.IPv4MatchSource{Net: net},
			),
		},
		{
			Name:  "dst IPv4Cond",
			Class: "dst=12.12.12.0/26",
			Tree: pktcls.NewCondIPv4(
				&pktcls.IPv4MatchDestination{Net: net},
			),
		},
		{
			Name:  "dscp IPv4Cond",
			Class: "dscp=0x2",
			Tree: pktcls.NewCondIPv4(
				&pktcls.IPv4MatchDSCP{DSCP: uint8(0x2)},
			),
		},
		{
			Name:  "NOT",
			Class: "NOT(dscp=0x2)",
			Tree: pktcls.CondNot{Operand: pktcls.NewCondIPv4(
				&pktcls.IPv4MatchDSCP{DSCP: uint8(0x2)},
			)},
		},
		{
			Name:  "BOOL",
			Class: "bool=true",
			Tree:  pktcls.CondBool(true),
		},
		{
			Name:  "single ALL",
			Class: "ALL(dscp=0x2)",
			Tree: pktcls.CondAllOf{pktcls.NewCondIPv4(
				&pktcls.IPv4MatchDSCP{DSCP: uint8(0x2)},
			)},
		},
		{
			Name:  "double ALL",
			Class: "ALL(dscp=0x2,dst=12.12.12.0/26)",
			Tree: pktcls.CondAllOf{
				pktcls.NewCondIPv4(&pktcls.IPv4MatchDSCP{DSCP: uint8(0x2)}),
				pktcls.NewCondIPv4(&pktcls.IPv4MatchDestination{Net: net})},
		},
		{
			Name:  "single ANY",
			Class: "ANY(dscp=0x2)",
			Tree: pktcls.CondAnyOf{pktcls.NewCondIPv4(
				&pktcls.IPv4MatchDSCP{DSCP: uint8(0x2)},
			)},
		},
		{
			Name:  "double ANY",
			Class: "ANY(dscp=0x2,dst=12.12.12.0/26)",
			Tree: pktcls.CondAnyOf{
				pktcls.NewCondIPv4(&pktcls.IPv4MatchDSCP{DSCP: uint8(0x2)}),
				pktcls.NewCondIPv4(&pktcls.IPv4MatchDestination{Net: net})},
		},
		{
			Name:  "srcport",
			Class: "srcport=12345",
			Tree: pktcls.NewCondPorts(&pktcls.PortMatchSource{
				MinPort: 12345,
				MaxPort: 12345,
			}),
		},
		{
			Name:  "dstport",
			Class: "dstport=12345",
			Tree: pktcls.NewCondPorts(&pktcls.PortMatchDestination{
				MinPort: 12345,
				MaxPort: 12345,
			}),
		},
		{
			Name:  "srcport range",
			Class: "srcport=100-199",
			Tree: pktcls.NewCondPorts(&pktcls.PortMatchSource{
				MinPort: 100,
				MaxPort: 199,
			}),
		},
		{
			Name:  "dstport range",
			Class: "dstport=100-199",
			Tree: pktcls.NewCondPorts(&pktcls.PortMatchDestination{
				MinPort: 100,
				MaxPort: 199,
			}),
		},
		{
			Name:  "ANY ALL NOT src dst dscp",
			Class: "ANY(dscp=0x2,ALL(dst=12.12.12.0/26,dscp=0x2, NOT(src=12.12.12.0/26)))",
			Tree: pktcls.CondAnyOf{
				pktcls.NewCondIPv4(&pktcls.IPv4MatchDSCP{DSCP: uint8(0x2)}),
				pktcls.CondAllOf{
					pktcls.NewCondIPv4(&pktcls.IPv4MatchDestination{Net: net}),
					pktcls.NewCondIPv4(&pktcls.IPv4MatchDSCP{DSCP: uint8(0x2)}),
					pktcls.CondNot{Operand: pktcls.NewCondIPv4(
						&pktcls.IPv4MatchSource{Net: net},
					)},
				},
			},
		},
		{
			Name:  "protocol TCP",
			Class: "protocol=TCP",
			Tree:  pktcls.NewCondIPv4(&pktcls.IPv4MatchProtocol{Protocol: uint8(6)}),
		},
		{
			Name:  "protocol udp",
			Class: "protocol=udp",
			Tree:  pktcls.NewCondIPv4(&pktcls.IPv4MatchProtocol{Protocol: uint8(17)}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			tree, err := pktcls.BuildClassTree(tc.Class)
			assert.NoError(t, err)
			assert.Equal(t, tc.Tree, tree)
		})
	}
}
