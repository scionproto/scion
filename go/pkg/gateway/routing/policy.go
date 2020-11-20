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

	"github.com/scionproto/scion/go/lib/addr"
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

// Match iterates through the list of rules in order and returns the first rule
// that matches. If no rule is matched, a rule with DefaultAction is returned.
func (p Policy) Match(from, to addr.IA, network *net.IPNet) Rule {
	for _, rule := range p.Rules {
		if rule.Match(from, to, network) {
			return rule
		}
	}
	return Rule{Action: p.DefaultAction}
}

// Rule represents a routing policy rule.
type Rule struct {
	Action  Action
	From    IAMatcher
	To      IAMatcher
	Network NetworkMatcher
	Comment string
}

// Match indicates if this rule matches the input.
func (r Rule) Match(from, to addr.IA, network *net.IPNet) bool {
	return r.From.Match(from) && r.To.Match(to) && r.Network.Match(network)
}

// IAMatcher matches ISD-AS.
type IAMatcher interface {
	Match(addr.IA) bool
}

// NetworkMatcher matches IP networks.
type NetworkMatcher interface {
	Match(*net.IPNet) bool
}

// Action represents the rule decision.
type Action int

// List of available actions.
const (
	UnknownAction Action = iota
	Accept
	Reject
	Advertise
)

func (a Action) String() string {
	switch a {
	case Accept:
		return "accept"
	case Reject:
		return "reject"
	case Advertise:
		return "advertise"
	default:
		return fmt.Sprintf("UNKNOWN (%d)", a)
	}
}
