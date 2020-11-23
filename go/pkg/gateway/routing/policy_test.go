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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/routing"
)

func TestPolicyCopy(t *testing.T) {
	testCases := map[string]struct {
		policy *routing.Policy
		action func(*routing.Policy)
	}{
		"change default action": {
			action: func(p *routing.Policy) {
				p.DefaultAction = routing.Accept
				return
			},
			policy: &routing.Policy{
				DefaultAction: routing.Reject,
			},
		},
		"change rule custom": {
			action: func(p *routing.Policy) {
				p.Rules[0].To = routing.SingleIAMatcher{IA: xtest.MustParseIA("1-ff00:0:113")}
				return
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

func TestPolicyMatch(t *testing.T) {
	policy := routing.Policy{
		Rules: []routing.Rule{
			{
				Action:  routing.Accept,
				From:    routing.NewIAMatcher(t, "1-ff00:0:110"),
				To:      routing.NewIAMatcher(t, "1-ff00:0:112"),
				Network: routing.NewNetworkMatcher(t, "127.0.0.0/24"),
			},
			{
				Action:  routing.Reject,
				From:    routing.NewIAMatcher(t, "1-ff00:0:110"),
				To:      routing.NewIAMatcher(t, "1-ff00:0:112"),
				Network: routing.NewNetworkMatcher(t, "!127.0.0.0/24"),
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
			},
		},
		DefaultAction: routing.Reject,
	}

	testCases := map[string]struct {
		From    addr.IA
		To      addr.IA
		Network string
		Rule    routing.Rule
	}{
		"first rule": {
			From:    xtest.MustParseIA("1-ff00:0:110"),
			To:      xtest.MustParseIA("1-ff00:0:112"),
			Network: "127.0.0.0/25",
			Rule:    policy.Rules[0],
		},
		"second rule": {
			From:    xtest.MustParseIA("1-ff00:0:110"),
			To:      xtest.MustParseIA("1-ff00:0:112"),
			Network: "127.0.1.0/25",
			Rule:    policy.Rules[1],
		},
		"third rule": {
			From:    xtest.MustParseIA("1-ff00:0:111"),
			To:      xtest.MustParseIA("1-ff00:0:112"),
			Network: "127.0.0.0/25",
			Rule:    policy.Rules[2],
		},
		"forth rule": {
			From:    xtest.MustParseIA("1-ff00:0:111"),
			To:      xtest.MustParseIA("1-ff00:0:112"),
			Network: "127.0.1.0/25",
			Rule:    policy.Rules[3],
		},
		"no match": {
			From:    xtest.MustParseIA("1-ff00:0:111"),
			To:      xtest.MustParseIA("1-ff00:0:112"),
			Network: "127.0.1.0/16",
			Rule:    routing.Rule{Action: routing.Reject},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rule := policy.Match(tc.From, tc.To, cidr(t, tc.Network))
			assert.Equal(t, tc.Rule, rule)
		})
	}
}
