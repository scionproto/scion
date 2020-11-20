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

package routing

import (
	"fmt"
	"net"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
)

// singleIAMatcher matches other ISD-AS numbers based on a single ISD-AS.
type singleIAMatcher struct {
	IA addr.IA
}

// Match matches the input ISD-AS if both the ISD and the AS number are the same
// as the one of the matcher. Zero values of ISD and AS in the matchers ISD-AS
// are treated as wildcards and match everything.
func (m singleIAMatcher) Match(ia addr.IA) bool {
	switch {
	case m.IA.IsZero():
		return true
	case m.IA.I == 0:
		return m.IA.A == ia.A
	case m.IA.A == 0:
		return m.IA.I == ia.I
	default:
		return m.IA.Equal(ia)
	}
}

func (m singleIAMatcher) String() string {
	return m.IA.String()
}

// negatedIAMatcher negates the result of the enclosed matcher.
type negatedIAMatcher struct {
	IAMatcher
}

// Match negates the result of the enclosed matcher.
func (m negatedIAMatcher) Match(ia addr.IA) bool {
	return !m.IAMatcher.Match(ia)
}

func (m negatedIAMatcher) String() string {
	return fmt.Sprintf("!%s", m.IAMatcher)
}

// allowedNetworkMatcher is a simple IP network matcher based on allowed IP
// networks.
type allowedNetworkMatcher struct {
	Allowed []*net.IPNet
}

// Match matches the input network if it is a subset of at least one allowed
// network.
func (m allowedNetworkMatcher) Match(network *net.IPNet) bool {
	for _, n := range m.Allowed {
		if isSubnet(network, n) {
			return true
		}
	}
	return false
}

func (m allowedNetworkMatcher) String() string {
	networks := make([]string, 0, len(m.Allowed))
	for _, network := range m.Allowed {
		networks = append(networks, network.String())
	}
	return strings.Join(networks, ",")
}

// negatedNetworkMatcher negates the result of the enclosed matcher.
type negatedNetworkMatcher struct {
	NetworkMatcher
}

// Match negates the result of the enclosed matcher.
func (m negatedNetworkMatcher) Match(network *net.IPNet) bool {
	return !m.NetworkMatcher.Match(network)
}

func (m negatedNetworkMatcher) String() string {
	return fmt.Sprintf("!%s", m.NetworkMatcher)
}

func isSubnet(sub, network *net.IPNet) bool {
	nLen, _ := network.Mask.Size()
	sLen, _ := sub.Mask.Size()
	return network.Contains(sub.IP) && nLen <= sLen
}
