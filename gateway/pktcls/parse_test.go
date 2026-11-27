// Copyright 2018 Anapaya Systems
// Copyright 2026 SCION Association
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

	"github.com/scionproto/scion/gateway/pktcls"
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

func TestTrafficClassValueChecks(t *testing.T) {
	testCases := []struct {
		Name        string
		Class       string
		ErrContains []string
	}{
		{Name: "large DSCP", Class: "dscp=0x3f"},
		{
			Name:        "DSCP above maximum",
			Class:       "dscp=0x40",
			ErrContains: []string{"DSCP value above maximum", "dscp=0x40", "max=0x3f"},
		},
		{Name: "source port range of one port", Class: "srcport=80-80"},
		{Name: "destination port range of one port", Class: "dstport=80-80"},
		{
			Name:        "empty source port range",
			Class:       "srcport=90-80",
			ErrContains: []string{"port range is empty", "keyword=srcport", "min=90", "max=80"},
		},
		{
			Name:        "empty destination port range",
			Class:       "dstport=90-80",
			ErrContains: []string{"port range is empty", "keyword=dstport", "min=90", "max=80"},
		},
		{
			Name:        "source port out of range with min>max",
			Class:       "srcport=99999-80",
			ErrContains: []string{"SRCPORT parsing failed!", "srcport=99999"},
		},
		{
			Name:        "destination port out of range with min>max",
			Class:       "dstport=99999-80",
			ErrContains: []string{"DSTPORT parsing failed!", "dstport=99999"},
		},
		{Name: "destination network", Class: "dst=10.1.2.0/24"},
		{Name: "destination host", Class: "dst=10.1.2.3/32"},
		{
			Name:  "destination CIDR with host bits",
			Class: "dst=10.1.2.3/24",
			ErrContains: []string{"CIDR has host bits", "cidr=10.1.2.3/24",
				"network=10.1.2.0/24"},
		},
		{
			Name:  "source CIDR with host bits",
			Class: "src=10.1.2.3/24",
			ErrContains: []string{"CIDR has host bits", "cidr=10.1.2.3/24",
				"network=10.1.2.0/24"},
		},
		{
			Name:        "nested value error",
			Class:       "ALL(dscp=0x2e, NOT(dscp=0x40))",
			ErrContains: []string{"DSCP value above maximum", "dscp=0x40"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			_, treeErr := pktcls.BuildClassTree(tc.Class)
			validateErr := pktcls.ValidateTrafficClass(tc.Class)
			for _, err := range []error{treeErr, validateErr} {
				if len(tc.ErrContains) == 0 {
					assert.NoError(t, err)
					continue
				}
				for _, text := range tc.ErrContains {
					assert.ErrorContains(t, err, text)
				}
			}
		})
	}
}

func TestMalformedClassNoPanic(t *testing.T) {
	for _, class := range []string{"not()", "not(", "any(not())"} {
		t.Run(class, func(t *testing.T) {
			var err error
			assert.NotPanics(t, func() { _, err = pktcls.BuildClassTree(class) })
			assert.Error(t, err)
			assert.NotPanics(t, func() { err = pktcls.ValidateTrafficClass(class) })
			assert.Error(t, err)
		})
	}
}
