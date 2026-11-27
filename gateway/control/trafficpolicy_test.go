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

package control_test

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/pktcls"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/path/pathpol"
)

var (
	ia111 = addr.MustParseIA("1-ff00:0:111")
	ia112 = addr.MustParseIA("1-ff00:0:112")
	ia113 = addr.MustParseIA("1-ff00:0:113")
)

const ia111Prefix = "10.1.0.0/16"

const (
	duplicateASesKeyMsg = "duplicate key, the parser merges the AS entries of each value: ases"
	duplicateASEntryMsg = "duplicate AS entry, only the last entry applies"
	noASEntriesMsg      = "file has no AS entries, so it gives no session policies"
	nullASEntryMsg      = "AS entry is null, it gives one session policy without prefixes"
	wildcardASEntryMsg  = "AS entry has a wildcard ISD-AS, " +
		"but an AS entry must name one remote AS"
	noCatchAllMsg = "no session policy matches all packets, " +
		"the SIG drops a packet that matches no session policy"
	falseClassMsg = "the SIG never uses this session policy, because its traffic class is false"
)

func unknownKeyMsg(key string) string {
	return "unknown key ignored: " + key
}

func duplicateKeyMsg(key string) string {
	return "duplicate key, the parser uses only one value: " + key
}

func sessionsKeyMsg(key string) string {
	return "key ignored, the key for session policies is SessionPolicies: " + key
}

func sessionOnlyKeyMsg(key string) string {
	return "key ignored, it is valid only on a session policy: " + key
}

func afterCatchAllMsg(catchAllID int) string {
	return fmt.Sprintf("the SIG never uses this session policy, "+
		"because session policy %d before it matches all packets", catchAllID)
}

func discardedASEntriesMsg(ias string) string {
	return "null ASes value, the parser discards the earlier AS entries: " + ias
}

func withSessionPolicies(sessions string) string {
	return fmt.Sprintf(`{"ASes": {%q: {"Nets": [%q], "SessionPolicies": %s}}}`,
		ia111, ia111Prefix, sessions)
}

func TestParseTrafficPolicyLegacyOrder(t *testing.T) {
	raw := []byte(`{"ASes": {
		"10-ff00:0:110": {"Nets": ["10.5.0.0/16"]},
		"1-ff00:0:113": {"Nets": ["10.3.0.0/16"]},
		"2-ff00:0:110": {"Nets": ["10.4.0.0/16"]},
		"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "PathCount": 2},
		"1-ff00:0:112": {"Nets": ["10.2.0.0/16"]}
	}}`)
	p, warnings, err := control.ParseTrafficPolicy(raw)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	ias := make([]addr.IA, 0, len(p))
	for _, sp := range p {
		ias = append(ias, sp.IA)
	}
	require.Equal(t, []addr.IA{ia111, ia112, ia113,
		addr.MustParseIA("2-ff00:0:110"), addr.MustParseIA("10-ff00:0:110")}, ias)
	assert.Equal(t, 2, p[0].PathCount)
}

func TestParseTrafficPolicyDuplicateASesKey(t *testing.T) {
	p, warnings, err := control.ParseTrafficPolicy([]byte(`{
		"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"]}},
		"ases": {"1-ff00:0:110": {"Nets": ["10.2.0.0/16"]}}
	}`))
	require.NoError(t, err)
	require.Len(t, p, 2)
	assert.Equal(t, addr.MustParseIA("1-ff00:0:110"), p[0].IA)
	assert.Equal(t, ia111, p[1].IA)
	assert.Equal(t, []control.TrafficPolicyWarning{{Msg: duplicateASesKeyMsg}}, warnings)
}

func TestParseTrafficPolicyNullASesValue(t *testing.T) {
	t.Run("null and then an object", func(t *testing.T) {
		p, warnings, err := control.ParseTrafficPolicy([]byte(
			`{"ASes": null, "ases": {"1-ff00:0:111": {}}}`))
		require.NoError(t, err)
		require.Len(t, p, 1)
		assert.Equal(t, ia111, p[0].IA)
		assert.Equal(t, []control.TrafficPolicyWarning{{Msg: duplicateASesKeyMsg}}, warnings)
	})

	t.Run("an object and then null", func(t *testing.T) {
		p, _, err := control.ParseTrafficPolicy([]byte(
			`{"ASes": {"1-ff00:0:111": {}}, "ases": null}`))
		assert.ErrorContains(t, err, "ASes must not be null")
		assert.Nil(t, p)
	})

	t.Run("an object, null, and then an object", func(t *testing.T) {
		p, warnings, err := control.ParseTrafficPolicy([]byte(`{
			"ASes": {"1-ff00:0:111": {"SessionPolicies": [{"ID": 1}]}},
			"ases": null,
			"ASES": {"1-ff00:0:112": {}, "1-ff00:0:111": {}}
		}`))
		require.NoError(t, err)
		require.Len(t, p, 2)
		assert.Equal(t, ia111, p[0].IA)
		assert.Equal(t, ia112, p[1].IA)
		assert.Equal(t, []control.TrafficPolicyWarning{
			{Msg: duplicateASesKeyMsg},
			{Severe: true, Msg: discardedASEntriesMsg("1-ff00:0:111")},
		}, warnings)
	})
}

func TestParseTrafficPolicySessionPolicyOrder(t *testing.T) {
	p, warnings, err := control.ParseTrafficPolicy([]byte(withSessionPolicies(`[
		{"ID": 9, "TrafficClass": "dscp=0x2e"},
		{"ID": 4, "TrafficClass": "dscp=0x0a"},
		{"ID": 7, "TrafficClass": "dscp=0x2e"},
		{"ID": 2},
		{"ID": 5, "TrafficClass": "dscp=0x0a"},
		{"ID": 1, "TrafficClass": "dscp=0x12"}
	]`)))
	require.NoError(t, err)
	ids := make([]int, 0, len(p))
	for _, sp := range p {
		ids = append(ids, sp.ID)
	}
	assert.Equal(t, []int{9, 4, 7, 2, 5, 1}, ids)
	assert.Equal(t, []control.TrafficPolicyWarning{
		{IA: &ia111, PolicyID: new(1), Severe: true, Msg: afterCatchAllMsg(2)},
	}, warnings)
}

func TestParseTrafficPolicySessionPolicies(t *testing.T) {
	raw := withSessionPolicies(`[
		{"ID": 7, "Name": "voice", "TrafficClass": "dscp=0x2e",
		 "PerformancePolicy": "shortest_path", "PathCount": 2},
		{"ID": 3}
	]`)
	expected := control.SessionPolicies{
		{
			IA:             ia111,
			ID:             7,
			Name:           "voice",
			TrafficMatcher: mustCond(t, "dscp=0x2e"),
			PerfPolicy:     control.DefaultPerfPolicy,
			PathPolicy:     control.DefaultPathPolicy,
			PathCount:      2,
			Prefixes:       xtest.MustParseCIDRs(t, ia111Prefix),
		},
		{
			IA:             ia111,
			ID:             3,
			TrafficMatcher: pktcls.CondTrue,
			PerfPolicy:     control.DefaultPerfPolicy,
			PathPolicy:     control.DefaultPathPolicy,
			PathCount:      control.DefaultPathCount,
			Prefixes:       xtest.MustParseCIDRs(t, ia111Prefix),
		},
	}
	p, warnings, err := control.ParseTrafficPolicy([]byte(raw))
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Equal(t, expected, p)
	assert.NotSame(t, p[0].Prefixes[0], p[1].Prefixes[0])
}

func TestParseTrafficPolicyCaseInsensitiveKeys(t *testing.T) {
	t.Run("legacy entry", func(t *testing.T) {
		p, warnings, err := control.ParseTrafficPolicy([]byte(
			`{"ases": {"1-ff00:0:111": {"nets": ["10.1.0.0/16"], "pathcount": 2}}}`))
		require.NoError(t, err)
		assert.Empty(t, warnings)
		require.Len(t, p, 1)
		assert.Equal(t, ia111, p[0].IA)
		assert.Equal(t, xtest.MustParseCIDRs(t, "10.1.0.0/16"), p[0].Prefixes)
		assert.Equal(t, 2, p[0].PathCount)
	})

	t.Run("session policy", func(t *testing.T) {
		p, warnings, err := control.ParseTrafficPolicy([]byte(`{"ASes": {"1-ff00:0:111":
			{"sessionpolicies": [{"id": 1, "trafficclass": "dscp=0x2e", "pathcount": 1},
			{"ID": 2}]}}}`))
		require.NoError(t, err)
		assert.Empty(t, warnings)
		expected := control.SessionPolicies{
			{
				IA:             ia111,
				ID:             1,
				TrafficMatcher: mustCond(t, "dscp=0x2e"),
				PerfPolicy:     control.DefaultPerfPolicy,
				PathPolicy:     control.DefaultPathPolicy,
				PathCount:      1,
				Prefixes:       []*net.IPNet{},
			},
			{
				IA:             ia111,
				ID:             2,
				TrafficMatcher: pktcls.CondTrue,
				PerfPolicy:     control.DefaultPerfPolicy,
				PathPolicy:     control.DefaultPathPolicy,
				PathCount:      control.DefaultPathCount,
				Prefixes:       []*net.IPNet{},
			},
		}
		assert.Equal(t, expected, p)
	})
}

func TestParseTrafficPolicyNullASEntry(t *testing.T) {
	p, _, err := control.ParseTrafficPolicy([]byte(`{"ASes": {"1-ff00:0:111": null}}`))
	require.NoError(t, err)
	require.Len(t, p, 1)
	assert.Equal(t, ia111, p[0].IA)
	assert.Equal(t, 0, p[0].ID)
	assert.Equal(t, pktcls.CondTrue, p[0].TrafficMatcher)
	assert.Equal(t, control.DefaultPathCount, p[0].PathCount)
	assert.Empty(t, p[0].Prefixes)
}

func TestParseTrafficPolicyValid(t *testing.T) {
	t.Run("boundary IDs", func(t *testing.T) {
		p, _, err := control.ParseTrafficPolicy([]byte(withSessionPolicies(
			`[{"ID": 0, "TrafficClass": "dscp=0x2e"}, {"ID": 255}]`)))
		require.NoError(t, err)
		require.Len(t, p, 2)
		assert.Equal(t, 0, p[0].ID)
		assert.Equal(t, 255, p[1].ID)
	})

	t.Run("same ID in two ASes", func(t *testing.T) {
		p, _, err := control.ParseTrafficPolicy([]byte(`{"ASes": {
			"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "SessionPolicies": [{"ID": 1}]},
			"1-ff00:0:112": {"Nets": ["10.2.0.0/16"], "SessionPolicies": [{"ID": 1}]}
		}}`))
		require.NoError(t, err)
		require.Len(t, p, 2)
		assert.Equal(t, ia111, p[0].IA)
		assert.Equal(t, ia112, p[1].IA)
		assert.Equal(t, 1, p[0].ID)
		assert.Equal(t, 1, p[1].ID)
	})

	t.Run("class names are case-sensitive", func(t *testing.T) {
		_, _, err := control.ParseTrafficPolicy([]byte(
			`{"TrafficClasses": {"voice": "dscp=0x2e", "Voice": "dscp=0x0"}, "ASes": {}}`))
		assert.NoError(t, err)
	})

	t.Run("isd_as key of a remote_isd_ases rule in mixed case", func(t *testing.T) {
		_, _, err := control.ParseTrafficPolicy([]byte(`{"PathPolicies": {"p":
			{"remote_isd_ases": [{"ISD_AS": "1-ff00:0:110"}]}}, "ASes": {}}`))
		assert.NoError(t, err)
	})

	t.Run("legacy PathCount zero gives the default path count", func(t *testing.T) {
		p, _, err := control.ParseTrafficPolicy([]byte(
			`{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "PathCount": 0}}}`))
		require.NoError(t, err)
		require.Len(t, p, 1)
		assert.Equal(t, control.DefaultPathCount, p[0].PathCount)
	})

	t.Run("legacy null PathCount gives the default path count", func(t *testing.T) {
		p, _, err := control.ParseTrafficPolicy([]byte(
			`{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "PathCount": null}}}`))
		require.NoError(t, err)
		require.Len(t, p, 1)
		assert.Equal(t, control.DefaultPathCount, p[0].PathCount)
	})

	t.Run("legacy null PathCount after a number keeps the number", func(t *testing.T) {
		p, _, err := control.ParseTrafficPolicy([]byte(
			`{"ASes": {"1-ff00:0:111": {"PathCount": 3, "PathCount": null}}}`))
		require.NoError(t, err)
		require.Len(t, p, 1)
		assert.Equal(t, 3, p[0].PathCount)
	})
}

func TestParseTrafficPolicyClassNames(t *testing.T) {
	testCases := map[string]struct {
		ClassName string
		Valid     bool
	}{
		"one letter":            {ClassName: "a", Valid: true},
		"underscore":            {ClassName: "ef_tagged", Valid: true},
		"hyphen and upper case": {ClassName: "to-app-X", Valid: true},
		"digit":                 {ClassName: "ICMPv6", Valid: true},
		"combinator keyword":    {ClassName: "all", Valid: true},
		"match keyword":         {ClassName: "dscp", Valid: true},
		"hex digits":            {ClassName: "cafe", Valid: true},

		"empty":            {ClassName: ""},
		"dot":              {ClassName: "voice.hi"},
		"digit first":      {ClassName: "1voice"},
		"underscore first": {ClassName: "_voice"},
		"hyphen first":     {ClassName: "-voice"},
		"non-ASCII letter": {ClassName: "vöice"},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			_, _, err := control.ParseTrafficPolicy([]byte(
				`{"TrafficClasses": {"` + tc.ClassName + `": "dscp=0x2e"}, "ASes": {}}`))
			if tc.Valid {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, "invalid traffic class name")
		})
	}
}

// The SIG allows at most MaxSessions sessions. A session policy gives one session for each
// remote gateway of its AS. Only the session configurator knows these gateways, thus it checks
// the limit. The parser must accept more session policies than MaxSessions.
func TestParseTrafficPolicyManySessionPolicies(t *testing.T) {
	t.Run("session policies", func(t *testing.T) {
		sessions := make([]string, 0, control.MaxSessionPolicyID+1)
		for id := range control.MaxSessionPolicyID + 1 {
			sessions = append(sessions, fmt.Sprintf(`{"ID": %d}`, id))
		}
		full := `"1-ff00:0:111": {"SessionPolicies": [` + strings.Join(sessions, ", ") + `]}`
		p, _, err := control.ParseTrafficPolicy([]byte(
			`{"ASes": {` + full + `, "1-ff00:0:112": {}}}`))
		require.NoError(t, err)
		assert.Len(t, p, control.MaxSessionPolicyID+2)
	})

	t.Run("legacy entries", func(t *testing.T) {
		n := control.MaxSessions + 1
		entries := make([]string, 0, n)
		for as := range n {
			entries = append(entries, fmt.Sprintf(`"1-ff00:1:%x": {}`, as))
		}
		p, _, err := control.ParseTrafficPolicy([]byte(
			`{"ASes": {` + strings.Join(entries, ", ") + `}}`))
		require.NoError(t, err)
		assert.Len(t, p, n)
	})
}

func TestParseTrafficPolicyFirstErrorInNameOrder(t *testing.T) {
	testCases := map[string]struct {
		Input       string
		ErrContains string
	}{
		"path policies": {
			Input:       `{"PathPolicies": {"z": null, "m": null, "b": null}, "ASes": {}}`,
			ErrContains: "path_policy=b",
		},
		"traffic class names": {
			Input: `{"TrafficClasses": {"z.": "dscp=0x2e", "m.": "dscp=0x2e",
				"b.": "dscp=0x2e"}, "ASes": {}}`,
			ErrContains: "traffic_class=b.",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			_, _, err := control.ParseTrafficPolicy([]byte(tc.Input))
			require.ErrorContains(t, err, tc.ErrContains)
		})
	}
}

func TestParseTrafficPolicyWarningsBeforeAnError(t *testing.T) {
	testCases := map[string]struct {
		Input       string
		ErrContains string
		Expected    []control.TrafficPolicyWarning
	}{
		"warning about the ASes object": {
			Input: `{"ASes": {
				"1-ff00:0:111": {"Nets": ["10.0.0.0/8"]},
				"1-FF00:0:111": {"Nets": ["10.0.0.1/8"]}
			}}`,
			ErrContains: "network must be canonical",
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, Severe: true, Msg: duplicateASEntryMsg},
			},
		},
		"warning about the AS entry with the error": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"],
				"nets": ["10.0.0.1/8"]}}}`,
			ErrContains: "network must be canonical",
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, Severe: true, Msg: duplicateKeyMsg("nets")},
			},
		},
		"warnings before and after a duplicate TrafficClasses key": {
			Input: `{"ConfigVersion": 1, "ConfigVersion": 2, "TrafficClasses": {},
				"TrafficClasses": {}, "Zones": 1, "Zones": 2, "ASes": {"1-ff00:0:111": {}}}`,
			ErrContains: "duplicate top-level key",
			Expected: []control.TrafficPolicyWarning{
				{Severe: true, Msg: unknownKeyMsg("Zones")},
				{Severe: true, Msg: duplicateKeyMsg("ConfigVersion")},
				{Severe: true, Msg: duplicateKeyMsg("Zones")},
			},
		},
		"duplicate ASes key with a null value": {
			Input:       `{"ASes": {"1-ff00:0:111": {}}, "ases": null}`,
			ErrContains: "ASes must not be null",
			Expected:    []control.TrafficPolicyWarning{{Msg: duplicateASesKeyMsg}},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			p, warnings, err := control.ParseTrafficPolicy([]byte(tc.Input))
			assert.ErrorContains(t, err, tc.ErrContains)
			assert.Nil(t, p)
			assert.ElementsMatch(t, tc.Expected, warnings)
		})
	}
}

func TestResolvePathPolicies(t *testing.T) {
	raw := map[string]json.RawMessage{
		"base":  json.RawMessage(`{"acl": ["- 2", "+"]}`),
		"child": json.RawMessage(`{"extends": ["base"], "sequence": "1-ff00:0:110#0 0*"}`),
		"empty": json.RawMessage(`{}`),
	}
	p, err := control.ResolvePathPolicies(raw)
	require.NoError(t, err)
	require.Len(t, p, 3)
	assert.Equal(t, "child", p["child"].Name)
	assert.Equal(t, p["base"].ACL, p["child"].ACL)
	require.NotNil(t, p["child"].Sequence)
	assert.Equal(t, "1-ff00:0:110#0 0*", p["child"].Sequence.String())
	assert.Equal(t, &pathpol.Policy{Name: "empty"}, p["empty"])
}

func TestResolvePathPoliciesDiamond(t *testing.T) {
	raw := map[string]json.RawMessage{
		"a": json.RawMessage(`{"extends": ["b", "c"]}`),
		"b": json.RawMessage(`{"extends": ["d"]}`),
		"c": json.RawMessage(`{"extends": ["d"]}`),
		"d": json.RawMessage(`{"acl": ["- 2", "+"]}`),
	}
	p, err := control.ResolvePathPolicies(raw)
	require.NoError(t, err)
	require.Len(t, p, 4)
	assert.Equal(t, p["d"].ACL, p["a"].ACL)
}

func TestResolvePathPoliciesSortsOptions(t *testing.T) {
	raw := map[string]json.RawMessage{
		"p": json.RawMessage(`{"options": [
			{"weight": 1, "policy": {"acl": ["- 1", "+"]}},
			{"weight": 3, "policy": {"options": [
				{"weight": 1, "policy": {}}, {"weight": 2, "policy": {}}
			]}},
			{"weight": 2, "policy": {"sequence": "0*"}}
		]}`),
	}
	p, err := control.ResolvePathPolicies(raw)
	require.NoError(t, err)
	options := p["p"].Options
	require.Len(t, options, 3)
	assert.Equal(t, 3, options[0].Weight)
	assert.Equal(t, 2, options[1].Weight)
	assert.Equal(t, 1, options[2].Weight)
	nested := options[0].Policy.Options
	require.Len(t, nested, 2)
	assert.Equal(t, 2, nested[0].Weight)
	assert.Equal(t, 1, nested[1].Weight)
}

func TestParseTrafficPolicyWarnings(t *testing.T) {
	type testCase struct {
		Input    string
		Expected []control.TrafficPolicyWarning
	}
	testCases := map[string]testCase{
		"unknown top-level key": {
			Input: `{"ConfigVersion": 1, "Routes": {}, "ASes": {"1-ff00:0:111": {}}}`,
			Expected: []control.TrafficPolicyWarning{
				{Severe: true, Msg: unknownKeyMsg("Routes")},
			},
		},
		"top-level SessionPolicies key": {
			Input: `{"SessionPolicies": [{"ID": 1}], "ASes": {"1-ff00:0:111": {}}}`,
			Expected: []control.TrafficPolicyWarning{
				{Severe: true, Msg: unknownKeyMsg("SessionPolicies")},
			},
		},
		"no ASes key": {
			Input:    `{}`,
			Expected: []control.TrafficPolicyWarning{{Severe: true, Msg: noASEntriesMsg}},
		},
		"no ASes key with a known key": {
			Input:    `{"ConfigVersion": 1}`,
			Expected: []control.TrafficPolicyWarning{{Severe: true, Msg: noASEntriesMsg}},
		},
		"empty ASes object": {
			Input:    `{"ASes": {}}`,
			Expected: []control.TrafficPolicyWarning{{Severe: true, Msg: noASEntriesMsg}},
		},
		"two empty ASes objects": {
			Input: `{"ASes": {}, "ases": {}}`,
			Expected: []control.TrafficPolicyWarning{
				{Msg: duplicateASesKeyMsg},
				{Severe: true, Msg: noASEntriesMsg},
			},
		},
		"unknown AS key": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "Sigs": {}}}}`,
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, Severe: true, Msg: unknownKeyMsg("Sigs")},
			},
		},
		"Sessions key next to SessionPolicies": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"],
				"SessionPolicies": [{"ID": 1}], "Sessions": []}}}`,
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, Severe: true, Msg: sessionsKeyMsg("Sessions")},
			},
		},
		"unknown keys in sorted order": {
			Input: `{"ASes": {"1-ff00:0:111": {"C": 1, "A": 2, "B": 3}}}`,
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, Severe: true, Msg: unknownKeyMsg("A")},
				{IA: &ia111, Severe: true, Msg: unknownKeyMsg("B")},
				{IA: &ia111, Severe: true, Msg: unknownKeyMsg("C")},
			},
		},
		"session key on a legacy AS entry": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"],
				"TrafficClass": "dscp=0x2e", "pathpolicy": "p", "PerformancePolicy": "latency"}}}`,
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, Severe: true, Msg: sessionOnlyKeyMsg("PerformancePolicy")},
				{IA: &ia111, Severe: true, Msg: sessionOnlyKeyMsg("TrafficClass")},
				{IA: &ia111, Severe: true, Msg: sessionOnlyKeyMsg("pathpolicy")},
			},
		},
		"null AS entry": {
			Input:    `{"ASes": {"1-ff00:0:111": null}}`,
			Expected: []control.TrafficPolicyWarning{{IA: &ia111, Msg: nullASEntryMsg}},
		},
		"wildcard AS entry": {
			Input: `{"ASes": {"1-0": {"Nets": ["10.1.0.0/16"]}}}`,
			Expected: []control.TrafficPolicyWarning{
				{IA: new(addr.MustParseIA("1-0")), Severe: true, Msg: wildcardASEntryMsg},
			},
		},
		"duplicate top-level key": {
			Input: `{"ConfigVersion": 1, "configversion": 2, "ASes": {"1-ff00:0:111": {}}}`,
			Expected: []control.TrafficPolicyWarning{
				{Severe: true, Msg: duplicateKeyMsg("configversion")},
			},
		},
		"duplicate AS entry": {
			Input: `{"ASes": {"1-ff00:0:111": {}, "1-FF00:0:111": {}}}`,
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, Severe: true, Msg: duplicateASEntryMsg},
			},
		},
		"duplicate AS entry in two ASes keys": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"]}},
				"ases": {"1-ff00:0:111": {}}}`,
			Expected: []control.TrafficPolicyWarning{
				{Msg: duplicateASesKeyMsg},
				{IA: &ia111, Severe: true, Msg: duplicateASEntryMsg},
			},
		},
		"three spellings of one ISD-AS key give one warning": {
			Input: `{"ASes": {"1-ff00:0:111": {}, "1-FF00:0:111": {}, "1-ff00:0:111": {}}}`,
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, Severe: true, Msg: duplicateASEntryMsg},
			},
		},
		"duplicate AS key": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "nets": []}}}`,
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, Severe: true, Msg: duplicateKeyMsg("nets")},
			},
		},
		"no catch-all session": {
			Input: withSessionPolicies(`[{"ID": 1, "TrafficClass": "dscp=0x2e"}]`),
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, Severe: true, Msg: noCatchAllMsg},
			},
		},
		"session after a catch-all session": {
			Input: withSessionPolicies(`[{"ID": 1}, {"ID": 2, "TrafficClass": "dscp=0x2e"}]`),
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, PolicyID: new(2), Severe: true, Msg: afterCatchAllMsg(1)},
			},
		},
		"warning about a session policy with a name": {
			Input: withSessionPolicies(`[{"ID": 1},
				{"ID": 2, "Name": "voice", "TrafficClass": "dscp=0x2e"}]`),
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, PolicyID: new(2), PolicyName: "voice", Severe: true,
					Msg: afterCatchAllMsg(1)},
			},
		},
		"false class never matches": {
			Input: withSessionPolicies(`[{"ID": 1, "TrafficClass": "bool=false"}, {"ID": 2}]`),
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, PolicyID: new(1), Severe: true, Msg: falseClassMsg},
			},
		},
		"false class after a catch-all gives one warning": {
			Input: withSessionPolicies(`[{"ID": 1}, {"ID": 2, "TrafficClass": "bool=false"}]`),
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, PolicyID: new(2), Severe: true, Msg: falseClassMsg},
			},
		},
		"same class after a catch-all is a failover session": {
			Input: withSessionPolicies(`[{"ID": 1, "TrafficClass": "dscp=0x2e"}, {"ID": 2},
				{"ID": 3, "TrafficClass": "DSCP=0x2e"}]`),
		},
		"second catch-all is a failover session": {
			Input: withSessionPolicies(`[{"ID": 1}, {"ID": 2, "PathCount": 2},
				{"ID": 3, "TrafficClass": "bool=true"}]`),
		},
		"explicit true is a catch-all": {
			Input: withSessionPolicies(`[{"ID": 1, "TrafficClass": "dscp=0x2e"},
				{"ID": 2, "TrafficClass": "bool=true"}]`),
		},
		"legacy entry needs no catch-all warning": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"]}}}`,
		},
	}
	for _, key := range []string{"Sessions", "SessionPolicy", "sessionpolicy", "SESSIONS"} {
		testCases[key+" key on an AS entry"] = testCase{
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "` + key +
				`": [{"ID": 1}]}}}`,
			Expected: []control.TrafficPolicyWarning{
				{IA: &ia111, Severe: true, Msg: sessionsKeyMsg(key)},
			},
		}
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			_, warnings, err := control.ParseTrafficPolicy([]byte(tc.Input))
			require.NoError(t, err)
			assert.Equal(t, tc.Expected, warnings)
		})
	}
}

func TestParseTrafficPolicyErrors(t *testing.T) {
	type testCase struct {
		Input       string
		ErrContains []string
		ErrIs       error
	}
	testCases := map[string]testCase{
		"JSON syntax error gives the line and the column": {
			Input:       "{\"ASes\": {\n  \"1-ff00:0:111\": {\"Nets\": [\"10.1.0.0/16\"],}\n}}",
			ErrContains: []string{"parsing JSON", "line=2", "column=44"},
		},
		"JSON type error gives the line": {
			Input:       "{\n  \"ASes\": {},\n  \"ConfigVersion\": \"one\"\n}",
			ErrContains: []string{"parsing JSON", "line=3"},
		},
		"file is an array": {
			Input:       `[]`,
			ErrContains: []string{"parsing JSON", "line=1"},
		},
		"ASes is an array": {
			Input:       `{"ASes": []}`,
			ErrContains: []string{"parsing JSON", "key=ASes"},
		},
		"ASes is a string": {
			Input:       `{"ASes": "1-ff00:0:111"}`,
			ErrContains: []string{"parsing JSON", "key=ASes"},
		},
		"second ASes value is an array": {
			Input:       `{"ASes": {"1-ff00:0:111": {}}, "ases": []}`,
			ErrContains: []string{"parsing JSON", "key=ASes"},
		},
		"invalid ISD-AS key": {
			Input:       `{"ASes": {"not-an-ia": {}}}`,
			ErrContains: []string{"parsing ISD-AS", "key=ASes", "isd_as=not-an-ia"},
		},
		"invalid ISD-AS key after a valid key": {
			Input:       `{"ASes": {"1-ff00:0:111": {}, "1-ff00:0:11x": {}}}`,
			ErrContains: []string{"parsing ISD-AS", "key=ASes", "isd_as=1-ff00:0:11x"},
		},
		"duplicate AS entry with SessionPolicies first": {
			Input: `{"ASes": {"1-ff00:0:111": {"SessionPolicies": [{"ID": 1}]},
				"1-FF00:0:111": {"Nets": ["10.1.0.0/16"]}}}`,
			ErrContains: []string{"duplicate AS entry with SessionPolicies",
				"isd_as=1-ff00:0:111"},
		},
		"duplicate AS entry with SessionPolicies last": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"]}},
				"ases": {"1-ff00:0:111": {"SessionPolicies": [{"ID": 1}]}}}`,
			ErrContains: []string{"duplicate AS entry with SessionPolicies",
				"isd_as=1-ff00:0:111"},
		},
		"error in the second AS entry names its IA": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"]},
				"1-ff00:0:112": {"SessionPolicies": [{"ID": 1, "TrafficClass": "dscp=zz"}]}}}`,
			ErrContains: []string{"parsing TrafficClass", "isd_as=1-ff00:0:112"},
		},
		"negative legacy PathCount": {
			Input:       `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "PathCount": -1}}}`,
			ErrContains: []string{"PathCount must not be negative", "isd_as=1-ff00:0:111"},
		},
		"AS entry is not an object": {
			Input:       `{"ASes": {"1-ff00:0:111": 5}}`,
			ErrContains: []string{"parsing AS entry"},
		},
		"empty SessionPolicies": {
			Input:       withSessionPolicies(`[]`),
			ErrContains: []string{"SessionPolicies must not be empty", "isd_as=1-ff00:0:111"},
		},
		"AS-level PathCount with SessionPolicies": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "PathCount": 2,
				"SessionPolicies": [{"ID": 1}]}}}`,
			ErrContains: []string{"PathCount must be set on each session policy"},
		},
		"null AS-level PathCount with SessionPolicies": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "PathCount": null,
				"SessionPolicies": [{"ID": 1}]}}}`,
			ErrContains: []string{"PathCount must be set on each session policy"},
		},
		"session without ID": {
			Input:       withSessionPolicies(`[{"Name": "x"}]`),
			ErrContains: []string{"ID must be set"},
		},
		"null session": {
			Input:       withSessionPolicies(`[{"ID": 1}, null]`),
			ErrContains: []string{"session policy must not be null", "index=1"},
		},
		"negative ID": {
			Input:       withSessionPolicies(`[{"ID": -1}]`),
			ErrContains: []string{"ID out of range"},
		},
		"ID above 255": {
			Input:       withSessionPolicies(`[{"ID": 256}]`),
			ErrContains: []string{"ID out of range"},
		},
		"duplicate ID": {
			Input: withSessionPolicies(`[{"ID": 1}, {"ID": 1}]`),
			ErrContains: []string{"duplicate session policy ID", "isd_as=1-ff00:0:111",
				"index=1", "id=1"},
		},
		"unknown session key": {
			Input:       withSessionPolicies(`[{"ID": 1, "Priority": 2}]`),
			ErrContains: []string{"unknown field"},
		},
		"null ID": {
			Input:       withSessionPolicies(`[{"ID": null}]`),
			ErrContains: []string{"value must not be null", "key=ID"},
		},
		"null TrafficClass": {
			Input:       withSessionPolicies(`[{"ID": 1, "TrafficClass": null}]`),
			ErrContains: []string{"value must not be null", "key=TrafficClass"},
		},
		"null PathPolicy": {
			Input:       withSessionPolicies(`[{"ID": 1, "PathPolicy": null}]`),
			ErrContains: []string{"value must not be null", "key=PathPolicy"},
		},
		"null session PathCount": {
			Input:       withSessionPolicies(`[{"ID": 1, "PathCount": null}]`),
			ErrContains: []string{"value must not be null", "key=PathCount"},
		},
		"invalid traffic class": {
			Input: withSessionPolicies(`[{"ID": 1, "TrafficClass": "dscp=zz"}]`),
			ErrContains: []string{"parsing TrafficClass", "isd_as=1-ff00:0:111", "index=0",
				"id=1"},
		},
		"class reference": {
			Input:       withSessionPolicies(`[{"ID": 1, "TrafficClass": "cls=3"}]`),
			ErrContains: []string{"class references (cls=) are not supported yet"},
		},
		"class reference to a name": {
			Input:       withSessionPolicies(`[{"ID": 1, "TrafficClass": "cls=voice"}]`),
			ErrContains: []string{"Parsing of traffic class failed"},
		},
		"class reference inside a combinator": {
			Input: withSessionPolicies(
				`[{"ID": 1, "TrafficClass": "any(dscp=0x2e, not(cls=3))"}]`),
			ErrContains: []string{"class references (cls=) are not supported yet"},
		},
		"class reference inside all": {
			Input: withSessionPolicies(
				`[{"ID": 1, "TrafficClass": "all(dscp=0x2e, cls=3)"}]`),
			ErrContains: []string{"class references (cls=) are not supported yet"},
		},
		"SessionPolicies is an object": {
			Input:       withSessionPolicies(`{"ID": 1}`),
			ErrContains: []string{"parsing AS entry", "isd_as=1-ff00:0:111"},
		},
		"null SessionPolicies": {
			Input:       withSessionPolicies(`null`),
			ErrContains: []string{"SessionPolicies must not be null"},
		},
		"null file": {
			Input:       `null`,
			ErrContains: []string{"must be an object, not null"},
		},
		"null ASes": {
			Input:       `{"ASes": null}`,
			ErrContains: []string{"ASes must not be null"},
		},
		"null ASes next to an unknown key": {
			Input:       `{"ASes": null, "AS": {"1-ff00:0:111": {}}}`,
			ErrContains: []string{"ASes must not be null"},
		},
		"typo in the ASes key": {
			Input: `{"AESs": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"]}}}`,
			ErrContains: []string{"file has no AS entries, but it has unknown keys",
				"unknown=AESs"},
		},
		"empty ASes object next to an unknown key": {
			Input: `{"ASes": {}, "Routes": {}}`,
			ErrContains: []string{"file has no AS entries, but it has unknown keys",
				"unknown=Routes"},
		},
		"two empty ASes objects next to an unknown key": {
			Input: `{"ASes": {}, "ases": {}, "Routes": {}}`,
			ErrContains: []string{"file has no AS entries, but it has unknown keys",
				"unknown=Routes"},
		},
		"empty TrafficClass": {
			Input: withSessionPolicies(`[{"ID": 1, "TrafficClass": ""}]`),
			ErrContains: []string{"value must not be empty, omit the key for the default",
				"key=TrafficClass", "isd_as=1-ff00:0:111", "index=0"},
		},
		"empty PathPolicy": {
			Input: withSessionPolicies(`[{"ID": 1, "PathPolicy": ""}]`),
			ErrContains: []string{"value must not be empty, omit the key for the default",
				"key=PathPolicy"},
		},
		"empty PerformancePolicy": {
			Input: withSessionPolicies(`[{"ID": 1, "PerformancePolicy": ""}]`),
			ErrContains: []string{"value must not be empty, omit the key for the default",
				"key=PerformancePolicy"},
		},
		"null Name": {
			Input:       withSessionPolicies(`[{"ID": 1, "Name": null}]`),
			ErrContains: []string{"value must not be null", "key=Name"},
		},
		"null PerformancePolicy": {
			Input:       withSessionPolicies(`[{"ID": 1, "PerformancePolicy": null}]`),
			ErrContains: []string{"value must not be null", "key=PerformancePolicy"},
		},
		"each traffic class of an AS is false": {
			Input: withSessionPolicies(`[{"ID": 1, "TrafficClass": "bool=false"},
				{"ID": 2, "TrafficClass": "bool=false"}]`),
			ErrContains: []string{"no session policy can match a packet",
				"isd_as=1-ff00:0:111"},
		},
		"duplicate SessionPolicies key": {
			Input: `{"ASes": {"1-ff00:0:111": {"SessionPolicies": [{"ID": 1}],
				"sessionpolicies": [{"ID": 2}]}}}`,
			ErrContains: []string{"duplicate SessionPolicies key"},
		},
		"duplicate session key": {
			Input:       withSessionPolicies(`[{"ID": 1, "id": 2}]`),
			ErrContains: []string{"duplicate key", "key=id"},
		},
		"duplicate traffic class name": {
			Input: `{"TrafficClasses": {"voice": "dscp=0x2e", "voice": "dscp=0x0"},
				"ASes": {}}`,
			ErrContains: []string{"duplicate name", "key=TrafficClasses", "name=voice"},
		},
		"duplicate path policy name": {
			Input:       `{"PathPolicies": {"p": {}, "p": {}}, "ASes": {}}`,
			ErrContains: []string{"duplicate name", "key=PathPolicies", "name=p"},
		},
		"duplicate top-level TrafficClasses key": {
			Input: `{"TrafficClasses": {"voice": "dscp=zz"}, "trafficclasses": {},
				"ASes": {}}`,
			ErrContains: []string{"duplicate top-level key", "key=trafficclasses"},
		},
		"duplicate top-level PathPolicies key": {
			Input:       `{"PathPolicies": {}, "pathpolicies": {}, "ASes": {}}`,
			ErrContains: []string{"duplicate top-level key", "key=pathpolicies"},
		},
		"null TrafficClasses": {
			Input:       `{"TrafficClasses": null, "ASes": {}}`,
			ErrContains: []string{"value must not be null", "key=TrafficClasses"},
		},
		"null PathPolicies": {
			Input:       `{"PathPolicies": null, "ASes": {}}`,
			ErrContains: []string{"value must not be null", "key=PathPolicies"},
		},
		"unknown path policy key": {
			Input:       `{"PathPolicies": {"p": {"sequnce": "0*"}}, "ASes": {}}`,
			ErrContains: []string{"unknown field"},
		},
		"duplicate path policy key": {
			Input:       `{"PathPolicies": {"p": {"acl": ["- 2", "+"], "acl": ["+"]}}, "ASes": {}}`,
			ErrContains: []string{"duplicate key", "key=acl", "path_policy=p"},
		},
		"unknown key in a remote_isd_ases rule": {
			Input: `{"PathPolicies": {"p": {"remote_isd_ases":
				[{"isd_as": "1-0", "rejct": true}]}}, "ASes": {}}`,
			ErrContains: []string{"parsing remote_isd_ases", "unknown field"},
		},
		"duplicate key in a remote_isd_ases rule": {
			Input: `{"PathPolicies": {"p": {"remote_isd_ases": [{"isd_as": "1-ff00:0:110",
				"reject": true, "reject": false}]}}, "ASes": {}}`,
			ErrContains: []string{"parsing remote_isd_ases", "duplicate key", "key=reject",
				"index=0"},
		},
		"null remote_isd_ases rule": {
			Input: `{"PathPolicies": {"p": {"remote_isd_ases": [{"isd_as": "1-0"}, null]}},
				"ASes": {}}`,
			ErrContains: []string{"parsing remote_isd_ases", "rule must not be null", "index=1"},
		},
		"null value in a remote_isd_ases rule": {
			Input: `{"PathPolicies": {"p": {"remote_isd_ases": [{"isd_as": null}]}},
				"ASes": {}}`,
			ErrContains: []string{"value must not be null", "key=isd_as", "index=0"},
		},
		"remote_isd_ases key in mixed case": {
			Input: `{"PathPolicies": {"p": {"Remote_ISD_ASes":
				[{"isd_as": "1-0", "rejct": true}]}}, "ASes": {}}`,
			ErrContains: []string{"parsing remote_isd_ases", "unknown field"},
		},
		"options key in mixed case": {
			Input:       `{"PathPolicies": {"p": {"Options": [{"weight": 1}]}}, "ASes": {}}`,
			ErrContains: []string{"option must have a policy"},
		},
		"duplicate path policy key in mixed case": {
			Input:       `{"PathPolicies": {"p": {"acl": ["+"], "ACL": ["- 2", "+"]}}, "ASes": {}}`,
			ErrContains: []string{"duplicate key", "key=ACL"},
		},
		"duplicate key in an option": {
			Input: `{"PathPolicies": {"p": {"options": [{"weight": 1, "weight": 9,
				"policy": {}}]}}, "ASes": {}}`,
			ErrContains: []string{"parsing option", "duplicate key", "key=weight"},
		},
		"option without a policy": {
			Input:       `{"PathPolicies": {"p": {"options": [{"weight": 1}]}}, "ASes": {}}`,
			ErrContains: []string{"option must have a policy", "index=0"},
		},
		"null option policy": {
			Input: `{"PathPolicies": {"p": {"options": [{"weight": 1, "policy": null}]}},
				"ASes": {}}`,
			ErrContains: []string{"option must have a policy"},
		},
		"null option": {
			Input:       `{"PathPolicies": {"p": {"options": [null]}}, "ASes": {}}`,
			ErrContains: []string{"option must not be null"},
		},
		"option policy with extends": {
			Input: `{"PathPolicies": {"base": {"acl": ["+"]}, "p": {"options":
				[{"weight": 1, "policy": {"extends": ["base"]}}]}}, "ASes": {}}`,
			ErrContains: []string{"option policy must not have extends"},
		},
		"duplicate key in an option policy": {
			Input: `{"PathPolicies": {"p": {"options": [{"weight": 1,
				"policy": {"acl": ["+"], "acl": ["- 2", "+"]}}]}}, "ASes": {}}`,
			ErrContains: []string{"duplicate key", "key=acl"},
		},
		"unknown key in an option": {
			Input: `{"PathPolicies": {"p": {"options": [{"weight": 1, "policy": {},
				"weigth": 2}]}}, "ASes": {}}`,
			ErrContains: []string{"unknown field"},
		},
		"unknown key in an option policy": {
			Input: `{"PathPolicies": {"p": {"options": [{"weight": 1,
				"policy": {"acel": ["+"]}}]}}, "ASes": {}}`,
			ErrContains: []string{"unknown field", "path_policy=p"},
		},
		"null acl": {
			Input:       `{"PathPolicies": {"p": {"acl": null}}, "ASes": {}}`,
			ErrContains: []string{"value must not be null", "key=acl", "path_policy=p"},
		},
		"null sequence": {
			Input:       `{"PathPolicies": {"p": {"sequence": null}}, "ASes": {}}`,
			ErrContains: []string{"value must not be null", "key=sequence"},
		},
		"null remote_isd_ases": {
			Input:       `{"PathPolicies": {"p": {"remote_isd_ases": null}}, "ASes": {}}`,
			ErrContains: []string{"value must not be null", "key=remote_isd_ases"},
		},
		"null local_isd_ases": {
			Input:       `{"PathPolicies": {"p": {"local_isd_ases": null}}, "ASes": {}}`,
			ErrContains: []string{"value must not be null", "key=local_isd_ases"},
		},
		"null options": {
			Input:       `{"PathPolicies": {"p": {"options": null}}, "ASes": {}}`,
			ErrContains: []string{"value must not be null", "key=options"},
		},
		"null extends": {
			Input:       `{"PathPolicies": {"p": {"extends": null}}, "ASes": {}}`,
			ErrContains: []string{"value must not be null", "key=extends"},
		},
		"null weight": {
			Input: `{"PathPolicies": {"p": {"options": [{"weight": null, "policy": {}}]}},
				"ASes": {}}`,
			ErrContains: []string{"parsing option", "value must not be null", "key=weight"},
		},
		"null key in an option policy": {
			Input: `{"PathPolicies": {"p": {"options": [{"weight": 1,
				"policy": {"sequence": null}}]}}, "ASes": {}}`,
			ErrContains: []string{"parsing option", "value must not be null", "key=sequence"},
		},
		"remote_isd_ases rule without isd_as": {
			Input: `{"PathPolicies": {"p": {"remote_isd_ases": [{"isd_as": "1-ff00:0:110"},
				{"reject": true}]}}, "ASes": {}}`,
			ErrContains: []string{"parsing remote_isd_ases", "rule must have isd_as",
				"index=1"},
		},
		"empty remote_isd_ases": {
			Input:       `{"PathPolicies": {"p": {"remote_isd_ases": []}}, "ASes": {}}`,
			ErrContains: []string{"parsing remote_isd_ases", "list must not be empty"},
		},
		"empty sequence": {
			Input:       `{"PathPolicies": {"p": {"sequence": ""}}, "ASes": {}}`,
			ErrContains: []string{"sequence must not be empty", "path_policy=p"},
		},
		"null local_isd_ases entry": {
			Input: `{"PathPolicies": {"p": {"local_isd_ases": ["1-ff00:0:110", null]}},
				"ASes": {}}`,
			ErrContains: []string{"parsing local_isd_ases", "entry must not be null",
				"index=1"},
		},
		"empty local_isd_ases": {
			Input:       `{"PathPolicies": {"p": {"local_isd_ases": []}}, "ASes": {}}`,
			ErrContains: []string{"parsing local_isd_ases", "list must not be empty"},
		},
		"empty path policy name": {
			Input:       `{"PathPolicies": {"": {"acl": ["+"]}}, "ASes": {}}`,
			ErrContains: []string{"path policy name must not be empty"},
		},
		"unknown path policy": {
			Input:       withSessionPolicies(`[{"ID": 1, "PathPolicy": "nope"}]`),
			ErrContains: []string{"unknown PathPolicy"},
		},
		"unknown performance policy": {
			Input:       withSessionPolicies(`[{"ID": 7, "PerformancePolicy": "fastest"}]`),
			ErrContains: []string{"unknown PerformancePolicy", "isd_as=1-ff00:0:111", "id=7"},
		},
		"null ACL entry": {
			Input:       `{"PathPolicies": {"p": {"acl": [null]}}, "ASes": {}}`,
			ErrContains: []string{"ACL entry must not be null"},
			ErrIs:       pathpol.ErrNullEntry,
		},
		"AS-level TrafficClass with SessionPolicies": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"],
				"TrafficClass": "dscp=0x2e", "SessionPolicies": [{"ID": 1}]}}}`,
			ErrContains: []string{"key must be set on a session policy", "key=TrafficClass"},
		},
		"AS-level PathPolicy with SessionPolicies": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "pathpolicy": "p",
				"SessionPolicies": [{"ID": 1}]}}}`,
			ErrContains: []string{"key must be set on a session policy", "key=pathpolicy"},
		},
		"AS-level PerformancePolicy with SessionPolicies": {
			Input: `{"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"],
				"PerformancePolicy": "latency", "SessionPolicies": [{"ID": 1}]}}}`,
			ErrContains: []string{"key must be set on a session policy",
				"key=PerformancePolicy"},
		},
		"session PathCount zero": {
			Input:       withSessionPolicies(`[{"ID": 1, "PathCount": 0}]`),
			ErrContains: []string{"PathCount must be 1 or more"},
		},
		"negative session PathCount": {
			Input:       withSessionPolicies(`[{"ID": 1, "PathCount": -1}]`),
			ErrContains: []string{"PathCount must be 1 or more"},
		},
		"named path policy": {
			Input: `{"PathPolicies": {"p": {"acl": ["+"]}},
				"ASes": {"1-ff00:0:111": {"Nets": ["10.1.0.0/16"],
				"SessionPolicies": [{"ID": 1, "PathPolicy": "p"}]}}}`,
			ErrContains: []string{"named path policies are not supported yet"},
		},
		"null path policy": {
			Input:       `{"PathPolicies": {"p": null}, "ASes": {}}`,
			ErrContains: []string{"path policy must not be null"},
		},
		"invalid ACL": {
			Input:       `{"PathPolicies": {"p": {"acl": ["- 1"]}}, "ASes": {}}`,
			ErrContains: []string{"parsing path policy", "path_policy=p"},
			ErrIs:       pathpol.ErrNoDefault,
		},
		"unknown extended path policy": {
			Input:       `{"PathPolicies": {"a": {"extends": ["b"]}}, "ASes": {}}`,
			ErrContains: []string{"Extended policy could not be found", "policy=b"},
		},
		"extends cycle": {
			Input: `{"PathPolicies": {"a": {"extends": ["b"]}, "b": {"extends": ["a"]}},
				"ASes": {}}`,
			ErrContains: []string{"cycle=a -> b -> a"},
		},
		"extends itself": {
			Input:       `{"PathPolicies": {"a": {"extends": ["a"]}}, "ASes": {}}`,
			ErrContains: []string{"cycle=a -> a"},
		},
		"null named traffic class": {
			Input:       `{"TrafficClasses": {"voice": null}, "ASes": {}}`,
			ErrContains: []string{"traffic class must not be null", "traffic_class=voice"},
		},
		"TrafficClasses is an array": {
			Input:       `{"TrafficClasses": ["voice"], "ASes": {}}`,
			ErrContains: []string{"parsing JSON", "key=TrafficClasses"},
		},
		"named traffic class is a number": {
			Input:       `{"TrafficClasses": {"voice": 5}, "ASes": {}}`,
			ErrContains: []string{"parsing JSON", "key=TrafficClasses"},
		},
		"PathPolicies is an array": {
			Input:       `{"PathPolicies": [], "ASes": {}}`,
			ErrContains: []string{"parsing JSON", "key=PathPolicies"},
		},
		"empty named traffic class": {
			Input:       `{"TrafficClasses": {"voice": ""}, "ASes": {}}`,
			ErrContains: []string{"traffic class must not be empty"},
		},
		"invalid named traffic class": {
			Input: `{"TrafficClasses": {"voice": "dscp=zz"}, "ASes": {}}`,
			ErrContains: []string{"parsing traffic class", "traffic_class=voice",
				"parsing TrafficClass"},
		},
		"class reference in a named traffic class": {
			Input:       `{"TrafficClasses": {"voice": "cls=3"}, "ASes": {}}`,
			ErrContains: []string{"class references (cls=) are not supported yet"},
		},
	}
	for _, perf := range []string{"latency", "jitter", "droprate"} {
		testCases["measured performance policy "+perf] = testCase{
			Input: withSessionPolicies(`[{"ID": 1, "PerformancePolicy": "` + perf + `"}]`),
			ErrContains: []string{"PerformancePolicy is not supported yet",
				"performance_policy=" + perf},
		}
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			p, _, err := control.ParseTrafficPolicy([]byte(tc.Input))
			require.Error(t, err)
			for _, text := range tc.ErrContains {
				assert.ErrorContains(t, err, text)
			}
			if tc.ErrIs != nil {
				assert.ErrorIs(t, err, tc.ErrIs)
			}
			assert.Nil(t, p)
		})
	}
}
