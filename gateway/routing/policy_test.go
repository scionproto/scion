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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/gateway/routing"
	"github.com/scionproto/scion/pkg/addr"
)

func TestPolicyCopy(t *testing.T) {
	testCases := map[string]struct {
		policy *routing.Policy
		action func(*routing.Policy)
	}{
		"change default action": {
			action: func(p *routing.Policy) {
				p.DefaultAction = routing.Accept
			},
			policy: &routing.Policy{
				DefaultAction: routing.Reject,
			},
		},
		"change rule custom": {
			action: func(p *routing.Policy) {
				p.Rules[0].To = routing.SingleIAMatcher{IA: addr.MustParseIA("1-ff00:0:113")}
			},
			policy: &routing.Policy{
				Rules: []routing.Rule{
					{
						Action:  routing.Accept,
						From:    routing.NewIAMatcher(t, "1-ff00:0:110"),
						To:      routing.NewIAMatcher(t, "1-ff00:0:112"),
						Network: routing.NewNetworkMatcher(t, "127.0.0.0/24"),
					},
				},
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := tc.policy.Copy()
			require.Equal(t, tc.policy, got)
			tc.action(got)
			require.NotEqual(t, tc.policy, got)
		})
	}
}

func TestNetworkMatch(t *testing.T) {

	acceptAll := func() *routing.Policy {
		return &routing.Policy{
			DefaultAction: routing.Accept,
		}
	}
	rejectAll := func() *routing.Policy {
		return &routing.Policy{
			DefaultAction: routing.Reject,
		}
	}
	acceptSome := func() *routing.Policy {
		return &routing.Policy{
			Rules: []routing.Rule{
				{
					Action:  routing.Accept,
					Network: routing.NewNetworkMatcher(t, "10.0.0.0/8"),
				},
				{
					Action:  routing.Accept,
					Network: routing.NewNetworkMatcher(t, "abcd::/16"),
				},
			},
			DefaultAction: routing.Reject,
		}
	}
	splitRange := func() *routing.Policy {
		return &routing.Policy{
			Rules: []routing.Rule{
				{
					Action:  routing.Accept,
					Network: routing.NewNetworkMatcher(t, "!10.0.1.0/24"),
				},
			},
			DefaultAction: routing.Reject,
		}
	}
	adjacentRanges := func() *routing.Policy {
		return &routing.Policy{
			Rules: []routing.Rule{
				{
					Action:  routing.Accept,
					Network: routing.NewNetworkMatcher(t, "10.0.0.0/24"),
				},
				{
					Action:  routing.Accept,
					Network: routing.NewNetworkMatcher(t, "10.0.1.0/24"),
				},
			},
			DefaultAction: routing.Reject,
		}
	}

	testCases := map[string]struct {
		policy *routing.Policy
		in     string
		out    string
	}{
		"accept all ipv4 full": {
			policy: acceptAll(),
			in:     "0.0.0.0/0",
			out:    "0.0.0.0/0",
		},
		"accept all ipv6 full": {
			policy: acceptAll(),
			in:     "::/0",
			out:    "::/0",
		},
		"accept all ipv4 partial": {
			policy: acceptAll(),
			in:     "10.0.0.0/8",
			out:    "10.0.0.0/8",
		},
		"accept all ipv6 partial": {
			policy: acceptAll(),
			in:     "abcd::/16",
			out:    "abcd::/16",
		},
		"reject all ipv4": {
			policy: rejectAll(),
			in:     "10.0.0.0/8",
			out:    "",
		},
		"reject all ipv6": {
			policy: rejectAll(),
			in:     "abcd::/16",
			out:    "",
		},
		"accept subset ipv4": {
			policy: acceptSome(),
			in:     "10.0.0.0/16",
			out:    "10.0.0.0/16",
		},
		"accept subset ipv6": {
			policy: acceptSome(),
			in:     "abcd:abcd::/32",
			out:    "abcd:abcd::/32",
		},
		"accept superset ipv4": {
			policy: acceptSome(),
			in:     "0.0.0.0/0",
			out:    "10.0.0.0/8",
		},
		"accept superset ipv6": {
			policy: acceptSome(),
			in:     "::/0",
			out:    "abcd::/16",
		},
		"split range": {
			policy: splitRange(),
			in:     "10.0.0.0/22",
			out:    "10.0.0.0/24,10.0.2.0/23",
		},
		"adjacent range": {
			policy: adjacentRanges(),
			in:     "10.0.0.0/23",
			out:    "10.0.0.0/23",
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ia := addr.MustParseIA("1-ff00:0:110")
			iaMatcher := routing.NewIAMatcher(t, "1-ff00:0:110")
			for i, r := range tc.policy.Rules {
				tc.policy.Rules[i] = routing.Rule{
					Action:  r.Action,
					Network: r.Network,
					From:    iaMatcher,
					To:      iaMatcher,
				}
			}
			out, err := tc.policy.Match(ia, ia, netip.MustParsePrefix(tc.in))
			assert.NoError(t, err)
			assert.Equal(t, tc.out, out.String())
		})
	}
}
