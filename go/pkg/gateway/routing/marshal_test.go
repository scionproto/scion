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

package routing_test

import (
	"flag"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/pkg/gateway/routing"
)

var update = flag.Bool("update", false, "update test golden files")

func TestPolicyMarshalText(t *testing.T) {
	for name, policy := range testPolicies(t) {
		raw, err := policy.MarshalText()
		require.NoError(t, err)
		if *update {
			err := ioutil.WriteFile(filepath.Join("./testdata", name), raw, 0666)
			require.NoError(t, err)
		}

		expected, err := ioutil.ReadFile(filepath.Join("./testdata", name))
		require.NoError(t, err)
		assert.Equal(t, string(expected), string(raw))
	}
}

func TestPolicyUnmarshalText(t *testing.T) {
	if *update {
		t.Skip("policies are being updated")
	}
	for name, expected := range testPolicies(t) {
		raw, err := ioutil.ReadFile(filepath.Join("./testdata", name))
		require.NoError(t, err)

		var policy routing.Policy
		require.NoError(t, policy.UnmarshalText(raw))
		assert.Equal(t, expected, policy)
	}
}

func testPolicies(t *testing.T) map[string]routing.Policy {
	return map[string]routing.Policy{
		"extensive.policy": {
			Rules: []routing.Rule{
				{
					Action:  routing.Accept,
					From:    routing.NewIAMatcher(t, "1-ff00:0:110"),
					To:      routing.NewIAMatcher(t, "1-ff00:0:112"),
					Network: routing.NewNetworkMatcher(t, "127.0.0.0/24,127.0.1.0/24"),
					Comment: "Rule one",
				},
				{
					Action:  routing.Reject,
					From:    routing.NewIAMatcher(t, "1-ff00:0:110"),
					To:      routing.NewIAMatcher(t, "1-ff00:0:112"),
					Network: routing.NewNetworkMatcher(t, "!127.0.0.0/24"),
					Comment: "Rule two",
				},
				{
					Action:  routing.Reject,
					From:    routing.NewIAMatcher(t, "1-0"),
					To:      routing.NewIAMatcher(t, "1-ff00:0:112"),
					Network: routing.NewNetworkMatcher(t, "127.0.0.0/24"),
				},
				{
					Action:  routing.Accept,
					From:    routing.NewIAMatcher(t, "1-ff00:0:111"),
					To:      routing.NewIAMatcher(t, "0-0"),
					Network: routing.NewNetworkMatcher(t, "127.0.1.0/24"),
					Comment: "Rule four",
				},
				{
					Action:  routing.Advertise,
					From:    routing.NewIAMatcher(t, "!1-ff00:0:111"),
					To:      routing.NewIAMatcher(t, "2-ff00:0:220"),
					Network: routing.NewNetworkMatcher(t, "127.0.1.0/24"),
					Comment: "Rule Five",
				},
			},
		},
		"ipv6.policy": {
			Rules: []routing.Rule{
				{
					Action:  routing.Accept,
					From:    routing.NewIAMatcher(t, "1-ff00:0:110"),
					To:      routing.NewIAMatcher(t, "1-ff00:0:112"),
					Network: routing.NewNetworkMatcher(t, "fd13:37::/64"),
					Comment: "Allow specific subnet from 1-ff00:0:110",
				},
				{
					Action:  routing.Reject,
					From:    routing.NewIAMatcher(t, "0-0"),
					To:      routing.NewIAMatcher(t, "1-ff00:0:112"),
					Network: routing.NewNetworkMatcher(t, "::/0,0.0.0.0/0"),
					Comment: "Reject everything",
				},
			},
		},
	}
}

func TestParseRule(t *testing.T) {
	testCases := map[string]struct {
		Input        []byte
		Expected     routing.Rule
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"space separated": {
			Input: []byte("accept 1-ff00:0:110  !1-ff00:0:111    127.0.0.0/24,127.0.0.0/24"),
			Expected: routing.Rule{
				Action:  routing.Accept,
				From:    routing.NewIAMatcher(t, "1-ff00:0:110"),
				To:      routing.NewIAMatcher(t, "!1-ff00:0:111"),
				Network: routing.NewNetworkMatcher(t, "127.0.0.0/24,127.0.0.0/24"),
			},
			ErrAssertion: assert.NoError,
		},
		"tab separated": {
			Input: []byte("accept\t1-ff00:0:110\t!1-ff00:0:111\t!127.0.0.0/24\t# Comment"),
			Expected: routing.Rule{
				Action:  routing.Accept,
				From:    routing.NewIAMatcher(t, "1-ff00:0:110"),
				To:      routing.NewIAMatcher(t, "!1-ff00:0:111"),
				Network: routing.NewNetworkMatcher(t, "!127.0.0.0/24"),
				Comment: "Comment",
			},
			ErrAssertion: assert.NoError,
		},
		"missing column": {
			Input:        []byte("reject 1-ff00:0:110 1-ff00:0:111"),
			ErrAssertion: assert.Error,
		},
		"too many columns": {
			Input:        []byte("reject 1-ff00:0:110 1-ff00:0:111 127.0.0.0/24 127.0.0.0/24"),
			ErrAssertion: assert.Error,
		},
		"invalid action": {
			Input:        []byte("party 1-ff00:0:110 1-ff00:0:111 127.0.0.0/24"),
			ErrAssertion: assert.Error,
		},
		"invalid from": {
			Input:        []byte("reject coffee 1-ff00:0:111 127.0.0.0/24"),
			ErrAssertion: assert.Error,
		},
		"invalid to": {
			Input:        []byte("reject 1-ff00:0:110 break 127.0.0.0/24"),
			ErrAssertion: assert.Error,
		},
		"invalid network": {
			Input:        []byte("reject 1-ff00:0:110 1-ff00:0:111 now!!!!"),
			ErrAssertion: assert.Error,
		},
		"partial input": {
			Input:        []byte("reject"),
			ErrAssertion: assert.Error,
		},
		"Empty input": {
			Input:        []byte(""),
			ErrAssertion: assert.Error,
		},
		"nil input": {
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			matcher, err := routing.ParseRule(tc.Input)
			tc.ErrAssertion(t, err)
			assert.Equal(t, tc.Expected, matcher)
		})
	}
}

func TestParseIAMatcher(t *testing.T) {
	testCases := map[string]struct {
		Input        []byte
		Expected     routing.IAMatcher
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"valid": {
			Input:        []byte("1-ff00:0:110"),
			Expected:     routing.NewIAMatcher(t, "1-ff00:0:110"),
			ErrAssertion: assert.NoError,
		},
		"valid 16 bit": {
			Input:        []byte("1-64496"),
			Expected:     routing.NewIAMatcher(t, "1-64496"),
			ErrAssertion: assert.NoError,
		},
		"valid 32 bit": {
			Input:        []byte("1-65536"),
			Expected:     routing.NewIAMatcher(t, "1-65536"),
			ErrAssertion: assert.NoError,
		},
		"negated": {
			Input:        []byte("!1-ff00:0:110"),
			Expected:     routing.NewIAMatcher(t, "!1-ff00:0:110"),
			ErrAssertion: assert.NoError,
		},
		"whitespace": {
			Input:        []byte("! 1-ff00:0:110"),
			ErrAssertion: assert.Error,
		},
		"multiple ISD-ASes": {
			Input:        []byte("1-ff00:0:110,1-ff00:0:111"),
			ErrAssertion: assert.Error,
		},
		"partial input": {
			Input:        []byte("1-ff"),
			ErrAssertion: assert.Error,
		},
		"Empty input": {
			Input:        []byte(""),
			ErrAssertion: assert.Error,
		},
		"nil input": {
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			matcher, err := routing.ParseIAMatcher(tc.Input)
			tc.ErrAssertion(t, err)
			assert.Equal(t, tc.Expected, matcher)
			if err != nil {
				return
			}
			assert.Equal(t, string(tc.Input), fmt.Sprint(matcher))
		})
	}
}

func TestParseNetworkMatcher(t *testing.T) {
	testCases := map[string]struct {
		Input        []byte
		Expected     routing.NetworkMatcher
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"valid": {
			Input:        []byte("127.0.0.0/24,fd13:37::/64"),
			Expected:     routing.NewNetworkMatcher(t, "127.0.0.0/24,fd13:37::/64"),
			ErrAssertion: assert.NoError,
		},
		"negated": {
			Input:        []byte("!127.0.0.0/24,127.0.1.0/24"),
			Expected:     routing.NewNetworkMatcher(t, "!127.0.0.0/24,127.0.1.0/24"),
			ErrAssertion: assert.NoError,
		},
		"whitespace": {
			Input:        []byte("! 127.0.0.0/24,127.0.1.0/24"),
			ErrAssertion: assert.Error,
		},
		"unknown symbol": {
			Input:        []byte("127.0.0.0/24|127.0.1.0/24"),
			ErrAssertion: assert.Error,
		},
		"partial input": {
			Input:        []byte("127.0.0.1/"),
			ErrAssertion: assert.Error,
		},
		"Empty input": {
			Input:        []byte(""),
			ErrAssertion: assert.Error,
		},
		"nil input": {
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			matcher, err := routing.ParseNetworkMatcher(tc.Input)
			tc.ErrAssertion(t, err)
			assert.Equal(t, tc.Expected, matcher)
			if err != nil {
				return
			}
			assert.Equal(t, string(tc.Input), fmt.Sprint(matcher))
		})
	}
}

func TestParseAction(t *testing.T) {
	testCases := map[string]struct {
		Input        []byte
		Expected     routing.Action
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"accept": {
			Input:        []byte(routing.Accept.String()),
			Expected:     routing.Accept,
			ErrAssertion: assert.NoError,
		},
		"reject": {
			Input:        []byte(routing.Reject.String()),
			Expected:     routing.Reject,
			ErrAssertion: assert.NoError,
		},
		"advertise": {
			Input:        []byte(routing.Advertise.String()),
			Expected:     routing.Advertise,
			ErrAssertion: assert.NoError,
		},
		"nil": {
			Input:        nil,
			Expected:     routing.UnknownAction,
			ErrAssertion: assert.Error,
		},
		"garbage": {
			Input:        []byte("garbage"),
			Expected:     routing.UnknownAction,
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			action, err := routing.ParseAction(tc.Input)
			tc.ErrAssertion(t, err)
			assert.Equal(t, tc.Expected, action)
			if err != nil {
				return
			}
			assert.Equal(t, string(tc.Input), action.String())
		})
	}
}
