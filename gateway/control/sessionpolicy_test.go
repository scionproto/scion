// Copyright 2020 Anapaya Systems
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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/control/mock_control"
	"github.com/scionproto/scion/gateway/pktcls"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/path/pathpol"
)

func TestLegacySessionPolicyAdapterParse(t *testing.T) {
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
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			parser := control.LegacySessionPolicyAdapter{}
			p, err := parser.Parse(context.Background(), tc.Input)
			assert.Equal(t, tc.Expected, p)
			tc.AssertErr(t, err)
		})
	}
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
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
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
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.ElementsMatch(t, tc.Expected, tc.Policies.RemoteIAs())
		})
	}
}

func TestCopyPathPolicy(t *testing.T) {
	input := &pathpol.Policy{
		ACL: &pathpol.ACL{
			Entries: []*pathpol.ACLEntry{
				{Action: pathpol.Allow},
			},
		},
	}
	p := control.CopyPathPolicy(input)
	assert.Equal(t, input, p)
	assert.NotSame(t, input, p)
}
