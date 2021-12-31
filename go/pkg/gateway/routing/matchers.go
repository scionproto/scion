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
type SingleIAMatcher struct {
	IA addr.IAInt
}

// Match matches the input ISD-AS if both the ISD and the AS number are the same
// as the one of the matcher. Zero values of ISD and AS in the matchers ISD-AS
// are treated as wildcards and match everything.
func (m SingleIAMatcher) Match(ia addr.IAInt) bool {
	switch {
	case m.IA.IsZero():
		return true
	case m.IA.I() == 0:
		return m.IA.A() == ia.A()
	case m.IA.A() == 0:
		return m.IA.I() == ia.I()
	default:
		return m.IA.Equal(ia)
	}
}

func (m SingleIAMatcher) String() string {
	return m.IA.String()
}

// negatedIAMatcher negates the result of the enclosed matcher.
type NegatedIAMatcher struct {
	IAMatcher
}

// Match negates the result of the enclosed matcher.
func (m NegatedIAMatcher) Match(ia addr.IAInt) bool {
	return !m.IAMatcher.Match(ia)
}

func (m NegatedIAMatcher) String() string {
	return fmt.Sprintf("!%s", m.IAMatcher)
}

// allowedNetworkMatcher is a simple IP network matcher based on allowed IP
// networks.
type AllowedNetworkMatcher struct {
	Allowed []*net.IPNet
}

// Match matches the input network if it is a subset of at least one allowed
// network.
func (m AllowedNetworkMatcher) Match(network *net.IPNet) bool {
	for _, n := range m.Allowed {
		if isSubnet(network, n) {
			return true
		}
	}
	return false
}

func (m AllowedNetworkMatcher) String() string {
	networks := make([]string, 0, len(m.Allowed))
	for _, network := range m.Allowed {
		networks = append(networks, network.String())
	}
	return strings.Join(networks, ",")
}

// negatedNetworkMatcher negates the result of the enclosed matcher.
type NegatedNetworkMatcher struct {
	NetworkMatcher
}

// Match negates the result of the enclosed matcher.
func (m NegatedNetworkMatcher) Match(network *net.IPNet) bool {
	return !m.NetworkMatcher.Match(network)
}

func (m NegatedNetworkMatcher) String() string {
	return fmt.Sprintf("!%s", m.NetworkMatcher)
}

func isSubnet(sub, network *net.IPNet) bool {
	nLen, _ := network.Mask.Size()
	sLen, _ := sub.Mask.Size()
	return network.Contains(sub.IP) && nLen <= sLen
}
