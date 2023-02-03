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
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"go4.org/netipx"

	"github.com/scionproto/scion/pkg/addr"
)

// Policy represents a set of rules. The rules of the policy are traversed in
// order during matching. The first rule that matches is returned. In case no
// rule matches, a default rule is returned.
//
// The default rule only has the action field set, everything else is the zero
// value. By default, the action is UnknownAction. It can be configured to the
// desired value by setting the DefaultAction field to the appropriate value.
type Policy struct {
	// Rules is a list of rules that the policy iterates during matching.
	Rules []Rule
	// DefaultAction is used as the action in the default rule. If not set, this
	// defaults to UnknownAction.
	DefaultAction Action
}

// Copy returns a deep-copied routing policy object.
// The method uses marshal/unmarshal to create a deep copy, if either
// marshaling or unmarshaling fails, this method panics.
func (p Policy) Copy() *Policy {
	// XXX(karampok): The simpler and the safer way to do a deep-copy is by
	// marshaling and unmarshaling the object. To my knowledge, there is no valid
	// object which can make the following code to panic. If there is, we should
	// refactor.
	raw, err := p.MarshalText()
	if err != nil {
		panic(err)
	}
	ret := &Policy{DefaultAction: p.DefaultAction}
	if err := ret.UnmarshalText(raw); err != nil {
		panic(err)
	}
	return ret
}

// Digest resturns the sha256 digest of the policy.
func (p Policy) Digest() []byte {
	raw, err := p.MarshalText()
	if err != nil {
		panic(err)
	}
	h := sha256.New()
	h.Write(raw)
	return h.Sum(nil)
}

// Match matches an IP range to the policy and returns the subranges that satisfy it.
func (p Policy) Match(from, to addr.IA, ipPrefix netip.Prefix) (IPSet, error) {
	// Compile the rules into a set of allowed addresses.
	var sb netipx.IPSetBuilder
	if p.DefaultAction == Accept {
		sb.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
		sb.AddPrefix(netip.MustParsePrefix("::/0"))
	}
	for i := len(p.Rules) - 1; i >= 0; i-- {
		rule := p.Rules[i]
		if !rule.From.Match(from) || !rule.To.Match(to) {
			continue
		}
		set, err := rule.Network.IPSet()
		if err != nil {
			return IPSet{}, err
		}
		switch rule.Action {
		case Accept:
			sb.AddSet(set)
		case Reject:
			sb.RemoveSet(set)
		}
	}
	// Intersect the supplied IP range with the allowed range to get the result.
	var nb netipx.IPSetBuilder
	nb.AddPrefix(ipPrefix)
	ns, err := nb.IPSet()
	if err != nil {
		return IPSet{}, err
	}
	sb.Intersect(ns)
	set, err := sb.IPSet()
	if err != nil {
		return IPSet{}, err
	}
	return IPSet{IPSet: *set}, nil
}

// Rule represents a routing policy rule.
type Rule struct {
	Action  Action
	From    IAMatcher
	To      IAMatcher
	Network NetworkMatcher
	NextHop net.IP
	Comment string
}

// IAMatcher matches ISD-AS.
type IAMatcher interface {
	Match(addr.IA) bool
}

// NetworkMatcher matches IP networks.
type NetworkMatcher struct {
	Allowed []netip.Prefix
	Negated bool
}

// IPSet returns a set containing all IPs allowed by the matcher.
func (m NetworkMatcher) IPSet() (*netipx.IPSet, error) {
	var sb netipx.IPSetBuilder
	for _, prefix := range m.Allowed {
		sb.AddPrefix(prefix)
	}
	if m.Negated {
		sb.Complement()
	}
	set, err := sb.IPSet()
	if err != nil {
		return nil, err
	}
	return set, nil
}

func (m NetworkMatcher) String() string {
	var negated string
	if m.Negated {
		negated = "!"
	}
	networks := make([]string, 0, len(m.Allowed))
	for _, network := range m.Allowed {
		networks = append(networks, network.String())
	}
	return negated + strings.Join(networks, ",")
}

// Action represents the rule decision.
type Action int

// List of available actions.
const (
	UnknownAction Action = iota
	Accept
	Reject
	Advertise
	RedistributeBGP
)

func (a Action) String() string {
	switch a {
	case Accept:
		return "accept"
	case Reject:
		return "reject"
	case Advertise:
		return "advertise"
	case RedistributeBGP:
		return "redistribute-bgp"
	default:
		return fmt.Sprintf("UNKNOWN (%d)", a)
	}
}
