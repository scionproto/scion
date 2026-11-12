// Copyright 2020 Anapaya Systems
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
	"context"
	"net"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/control/mock_control"
	"github.com/scionproto/scion/gateway/pktcls"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
)

func TestTrafficPolicyParserParse(t *testing.T) {
	testCases := map[string]struct {
		Input     []byte
		Expected  control.SessionPolicies
		AssertErr assert.ErrorAssertionFunc
	}{
		"nil input": {
			Input:     nil,
			Expected:  nil,
			AssertErr: assert.Error,
		},
		"garbage input": {
			Input:     []byte(`garbage`),
			Expected:  nil,
			AssertErr: assert.Error,
		},
		"garbage CIDR": {
			Input: []byte(`
			{
				"ASes": {
				  "1-ff00:0:110": {
					"Nets": [
					  "not cidr"
					]
				  }
				},
				"ConfigVersion": 300
			}
			`),
			Expected:  nil,
			AssertErr: assert.Error,
		},
		"invalid CIDR": {
			Input: []byte(`
			{
				"ASes": {
				  "1-ff00:0:110": {
					"Nets": [
					  "172.20.4.1/24"
					]
				  }
				},
				"ConfigVersion": 300
			}
			`),
			Expected:  nil,
			AssertErr: assert.Error,
		},
		"single AS": {
			Input: []byte(`
			{
				"ASes": {
				  "1-ff00:0:110": {
					"Nets": [
					  "172.20.4.0/24"
					]
				  }
				},
				"ConfigVersion": 300
			}
			`),
			Expected: control.SessionPolicies{
				control.SessionPolicy{
					ID:             0,
					IA:             addr.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy,
					PathCount:      1,
					Prefixes:       []*net.IPNet{xtest.MustParseCIDR(t, "172.20.4.0/24")},
				},
			},
			AssertErr: assert.NoError,
		},
		"session policies": {
			Input: []byte(`
			{
				"ASes": {
				  "1-ff00:0:110": {
					"Nets": [
					  "172.20.4.0/24"
					],
					"SessionPolicies": [
					  {"ID": 2, "Name": "voice", "TrafficClass": "dscp=0x2e"},
					  {"ID": 1}
					]
				  }
				},
				"ConfigVersion": 300
			}
			`),
			Expected: control.SessionPolicies{
				control.SessionPolicy{
					ID:             2,
					Name:           "voice",
					IA:             addr.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: mustCond(t, "dscp=0x2e"),
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy,
					PathCount:      1,
					Prefixes:       []*net.IPNet{xtest.MustParseCIDR(t, "172.20.4.0/24")},
				},
				control.SessionPolicy{
					ID:             1,
					IA:             addr.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy,
					PathCount:      1,
					Prefixes:       []*net.IPNet{xtest.MustParseCIDR(t, "172.20.4.0/24")},
				},
			},
			AssertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			parser := control.TrafficPolicyParser{}
			p, err := parser.Parse(context.Background(), tc.Input)
			assert.Equal(t, tc.Expected, p)
			tc.AssertErr(t, err)
		})
	}
}

type logEntry struct {
	Level  string
	Msg    string
	Fields []any
}

type fakeLogger struct {
	fields  []any
	entries *[]logEntry
}

func (l fakeLogger) New(ctx ...any) log.Logger {
	return fakeLogger{fields: append(slices.Clone(l.fields), ctx...), entries: l.entries}
}

func (l fakeLogger) Debug(msg string, ctx ...any) { l.add("debug", msg, ctx) }
func (l fakeLogger) Info(msg string, ctx ...any)  { l.add("info", msg, ctx) }
func (l fakeLogger) Error(msg string, ctx ...any) { l.add("error", msg, ctx) }
func (l fakeLogger) Enabled(log.Level) bool       { return true }

func (l fakeLogger) add(level, msg string, ctx []any) {
	*l.entries = append(*l.entries, logEntry{Level: level, Msg: msg,
		Fields: append(slices.Clone(l.fields), ctx...)})
}

func TestTrafficPolicyParserParseLogsWarnings(t *testing.T) {
	const msg = "Traffic policy file warning"

	t.Run("each warning", func(t *testing.T) {
		var entries []logEntry
		_, err := control.TrafficPolicyParser{}.Parse(
			log.CtxWith(context.Background(), fakeLogger{entries: &entries}),
			[]byte(`{"Routes": {}, "ASes": {
				"1-ff00:0:111": {"Nets": ["10.1.0.0/16"], "Sigs": {}},
				"1-ff00:0:112": null,
				"1-ff00:0:113": {"SessionPolicies": [{"ID": 1},
					{"ID": 2, "TrafficClass": "dscp=0x2e"},
					{"ID": 3, "Name": "voice", "TrafficClass": "dscp=0x0"}]}
			}}`))
		require.NoError(t, err)
		assert.Equal(t, []logEntry{
			{Level: "error", Msg: msg, Fields: []any{"warning", unknownKeyMsg("Routes")}},
			{Level: "error", Msg: msg,
				Fields: []any{"isd_as", ia111, "warning", unknownKeyMsg("Sigs")}},
			{Level: "info", Msg: msg, Fields: []any{"isd_as", ia112, "warning", nullASEntryMsg}},
			{Level: "error", Msg: msg, Fields: []any{"isd_as", ia113,
				"session_policy_id", 2, "warning", afterCatchAllMsg(1)}},
			{Level: "error", Msg: msg, Fields: []any{"isd_as", ia113,
				"session_policy_id", 3, "session_policy_name", "voice",
				"warning", afterCatchAllMsg(1)}},
		}, entries)
	})

	t.Run("warning before an error", func(t *testing.T) {
		var entries []logEntry
		_, err := control.TrafficPolicyParser{}.Parse(
			log.CtxWith(context.Background(), fakeLogger{entries: &entries}),
			[]byte(`{"ASes": {
				"1-ff00:0:111": {"Nets": ["10.0.0.0/8"]},
				"1-FF00:0:111": {"Nets": ["10.0.0.1/8"]}
			}}`))
		assert.ErrorContains(t, err, "network must be canonical")
		assert.Equal(t, []logEntry{
			{Level: "error", Msg: msg,
				Fields: []any{"isd_as", ia111, "warning", duplicateASEntryMsg}},
		}, entries)
	})
}

func TestLoadSessionPolicies(t *testing.T) {
	file, err := os.CreateTemp("", "control_sess_pol_load")
	require.NoError(t, err)
	filename := file.Name()
	file.Close()
	defer os.Remove(filename)

	testCases := map[string]struct {
		File      string
		Parser    func(*gomock.Controller) control.SessionPolicyParser
		Expected  control.SessionPolicies
		AssertErr assert.ErrorAssertionFunc
	}{
		"non-existing file": {
			File: "non-existing",
			Parser: func(ctrl *gomock.Controller) control.SessionPolicyParser {
				return mock_control.NewMockSessionPolicyParser(ctrl)
			},
			Expected:  nil,
			AssertErr: assert.Error,
		},
		"existing file, parsers error": {
			File: filename,
			Parser: func(ctrl *gomock.Controller) control.SessionPolicyParser {
				p := mock_control.NewMockSessionPolicyParser(ctrl)
				p.EXPECT().Parse(context.Background(), []byte{}).
					Return(nil, serrors.New("test error"))
				return p
			},
			Expected:  nil,
			AssertErr: assert.Error,
		},
		"existing file, parses": {
			File: filename,
			Parser: func(ctrl *gomock.Controller) control.SessionPolicyParser {
				p := mock_control.NewMockSessionPolicyParser(ctrl)
				p.EXPECT().Parse(context.Background(), []byte{}).
					Return(control.SessionPolicies{}, nil)
				return p
			},
			Expected:  control.SessionPolicies{},
			AssertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			p, err := control.LoadSessionPolicies(context.Background(), tc.File, tc.Parser(ctrl))
			assert.Equal(t, tc.Expected, p)
			tc.AssertErr(t, err)
		})
	}
}

func TestSessionPoliciesRemoteIAs(t *testing.T) {
	testCases := map[string]struct {
		Policies control.SessionPolicies
		Expected []addr.IA
	}{
		"nil": {
			Expected: []addr.IA{},
		},
		"empty": {
			Policies: control.SessionPolicies{},
			Expected: []addr.IA{},
		},
		"single entry": {
			Policies: control.SessionPolicies{
				control.SessionPolicy{IA: addr.MustParseIA("1-ff00:0:110")},
			},
			Expected: []addr.IA{addr.MustParseIA("1-ff00:0:110")},
		},
		"multiple entries with duplicates": {
			Policies: control.SessionPolicies{
				control.SessionPolicy{IA: addr.MustParseIA("1-ff00:0:110")},
				control.SessionPolicy{IA: addr.MustParseIA("1-ff00:0:110")},
				control.SessionPolicy{IA: addr.MustParseIA("1-ff00:0:111")},
			},
			Expected: []addr.IA{
				addr.MustParseIA("1-ff00:0:110"),
				addr.MustParseIA("1-ff00:0:111"),
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.ElementsMatch(t, tc.Expected, tc.Policies.RemoteIAs())
		})
	}
}

func TestSessionPolicyCopy(t *testing.T) {
	sp := control.SessionPolicy{
		IA:             addr.MustParseIA("1-ff00:0:110"),
		ID:             7,
		Name:           "voice",
		TrafficMatcher: mustCond(t, "dscp=0x2e"),
		PerfPolicy:     control.DefaultPerfPolicy,
		PathPolicy:     control.DefaultPathPolicy,
		PathCount:      2,
		Prefixes:       xtest.MustParseCIDRs(t, "10.1.0.0/16"),
	}
	v := reflect.ValueOf(sp)
	for field := range v.Type().Fields() {
		assert.False(t, v.FieldByIndex(field.Index).IsZero(),
			"set a value for the field %s", field.Name)
	}
	cp := sp.Copy()
	assert.Equal(t, sp, cp)
	assert.NotSame(t, sp.Prefixes[0], cp.Prefixes[0])
}
