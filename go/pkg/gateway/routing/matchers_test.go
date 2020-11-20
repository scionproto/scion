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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/routing"
)

func TestSingleIAMatcher(t *testing.T) {
	testCases := map[string]struct {
		Matcher    routing.IAMatcher
		Matches    []string
		NotMatches []string
	}{
		"match": {
			Matcher:    routing.NewIAMatcher(t, "1-ff00:0:110"),
			Matches:    []string{"1-ff00:0:110"},
			NotMatches: []string{"1-ff00:0:111", "2-ff00:0:110"},
		},
		"match wildcard": {
			Matcher: routing.NewIAMatcher(t, "0-0"),
			Matches: []string{"1-ff00:0:110"},
		},
		"match wildcard ISD": {
			Matcher:    routing.NewIAMatcher(t, "0-ff00:0:110"),
			Matches:    []string{"1-ff00:0:110", "2-ff00:0:110"},
			NotMatches: []string{"1-ff00:0:111"},
		},
		"match wildcard AS": {
			Matcher:    routing.NewIAMatcher(t, "1-0"),
			Matches:    []string{"1-ff00:0:110", "1-ff00:0:110"},
			NotMatches: []string{"2-ff00:0:110"},
		},
		"negated match": {
			Matcher:    routing.NewIAMatcher(t, "!1-ff00:0:110"),
			Matches:    []string{"1-ff00:0:111", "2-ff00:0:110"},
			NotMatches: []string{"1-ff00:0:110"},
		},
		"negated match wildcard": {
			Matcher:    routing.NewIAMatcher(t, "!0-0"),
			NotMatches: []string{"1-ff00:0:110"},
		},
		"negated match wildcard ISD": {
			Matcher:    routing.NewIAMatcher(t, "!0-ff00:0:110"),
			Matches:    []string{"1-ff00:0:111"},
			NotMatches: []string{"1-ff00:0:110", "2-ff00:0:110"},
		},
		"negated match wildcard AS": {
			Matcher:    routing.NewIAMatcher(t, "!1-0"),
			Matches:    []string{"2-ff00:0:110"},
			NotMatches: []string{"1-ff00:0:110", "1-ff00:0:110"},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, matches := range tc.Matches {
				assert.True(t, tc.Matcher.Match(xtest.MustParseIA(matches)), matches)
			}
			for _, notMatches := range tc.NotMatches {
				assert.False(t, tc.Matcher.Match(xtest.MustParseIA(notMatches)), notMatches)
			}
		})
	}
}

func TestAllowBlockNetworkMatcher(t *testing.T) {
	testCases := map[string]struct {
		Matcher    routing.NetworkMatcher
		Matches    []string
		NotMatches []string
	}{
		"allowed": {
			Matcher:    routing.NewNetworkMatcher(t, "127.0.0.0/24,127.0.1.0/24"),
			Matches:    []string{"127.0.1.0/24", "127.0.1.0/25", "127.0.0.0/24"},
			NotMatches: []string{"127.0.2.0/24", "127.0.0.0/16"},
		},
		"negated allowed": {
			Matcher:    routing.NewNetworkMatcher(t, "!127.0.0.0/24,127.0.1.0/24"),
			Matches:    []string{"127.0.2.0/24", "127.0.0.0/16"},
			NotMatches: []string{"127.0.1.0/24", "127.0.1.0/25", "127.0.0.0/24"},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, matches := range tc.Matches {
				assert.True(t, tc.Matcher.Match(cidr(t, matches)), matches)
			}
			for _, notMatches := range tc.NotMatches {
				assert.False(t, tc.Matcher.Match(cidr(t, notMatches)), notMatches)
			}
		})
	}
}

func TestIsSubnet(t *testing.T) {
	testCases := map[string]struct {
		Network  string
		Subnet   string
		IsSubnet bool
	}{
		"IPv4 true subnet": {
			Network:  "127.0.0.0/24",
			Subnet:   "127.0.0.0/26",
			IsSubnet: true,
		},
		"IPv4 equal net": {
			Network:  "127.0.0.0/24",
			Subnet:   "127.0.0.0/24",
			IsSubnet: true,
		},
		"IPv6 true subnet": {
			Network:  "::/56",
			Subnet:   "::/64",
			IsSubnet: true,
		},
		"IPv6 equal net": {
			Network:  "::/56",
			Subnet:   "::/56",
			IsSubnet: true,
		},
		"IPv4 super net": {
			Network:  "127.0.0.0/24",
			Subnet:   "127.0.0.0/18",
			IsSubnet: false,
		},
		"IPv6 super net": {
			Network:  "::/64",
			Subnet:   "::/56",
			IsSubnet: false,
		},
		"IPv4/IPv6": {
			Network:  "0.0.0.0/24",
			Subnet:   "::/24",
			IsSubnet: false,
		},
		"IPv6/IPv4": {
			Network:  "::/24",
			Subnet:   "0.0.0.0/24",
			IsSubnet: false,
		},
		"IPv4 disjoint": {
			Network:  "127.0.0.0/24",
			Subnet:   "127.0.1.0/24",
			IsSubnet: false,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			network, subnet := cidr(t, tc.Network), cidr(t, tc.Subnet)
			assert.Equal(t, tc.IsSubnet, routing.IsSubnet(subnet, network))
		})
	}
}

func cidr(t *testing.T, network string) *net.IPNet {
	_, n, err := net.ParseCIDR(network)
	require.NoError(t, err)
	return n
}
