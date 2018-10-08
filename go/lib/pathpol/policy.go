// Copyright 2018 ETH Zurich
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

// Package pathpol implements path policies, documentation in doc/PathPolicy.md
//
// A policy has an Act() method that takes an AppPathSet and returns a filtered AppPathSet
package pathpol

import (
	"sort"

	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

var _ pktcls.Action = (*Policy)(nil)

// Policy is a path policy object
// Currently implemented: ACL, Sequence, Extends and Options. See planned features in
// doc/PathPolicy.md.
type Policy struct {
	Name     string
	Extends  []*Policy
	ACL      *ACL
	Sequence Sequence
	Options  []Option
}

func NewPolicy(name string, extends []*Policy, acl *ACL, sequence Sequence,
	options []Option) *Policy {

	policy := &Policy{Name: name, Extends: extends, ACL: acl, Sequence: sequence, Options: options}
	// Apply all extended policies
	policy.applyExtended()
	// Sort options by weight, descending
	sort.Slice(policy.Options, func(i, j int) bool {
		return policy.Options[i].Weight > policy.Options[j].Weight
	})
	return policy
}

// Act filters the path set according the policy
func (p *Policy) Act(values interface{}) interface{} {
	inputSet := values.(spathmeta.AppPathSet)
	// Filter on ACL
	resultSet := p.ACL.Eval(inputSet)
	// Filter on Sequence
	resultSet = p.Sequence.Eval(resultSet)
	// Filter on sub policies
	if len(p.Options) > 0 {
		resultSet = p.evalOptions(resultSet)
	}
	return resultSet
}

func (p *Policy) GetName() string {
	return p.Name
}

func (p *Policy) SetName(name string) {
	p.Name = name
}

func (p *Policy) Type() string {
	return "Policy"
}

// applyExtended adds attributes of extended policies to the extending policy if they are not
// already set
func (p *Policy) applyExtended() {
	// traverse in reverse s.t. last entry of the list has precedence
	for i := len(p.Extends) - 1; i >= 0; i-- {
		policy := p.Extends[i]
		// Replace ACL
		if p.ACL == nil && policy.ACL != nil {
			p.ACL = policy.ACL
		}
		// Replace options
		if len(p.Options) == 0 {
			p.Options = policy.Options
		}
		// Replace Sequence
		if len(p.Sequence) == 0 {
			p.Sequence = policy.Sequence
		}
	}
	// all sub-policies have been set, remove them
	p.Extends = nil
}

// evalOptions evaluates the options of a policy and returns the pathSet that matches the option
// with the heighest weight
func (p *Policy) evalOptions(inputSet spathmeta.AppPathSet) spathmeta.AppPathSet {
	subPolicySet := make(spathmeta.AppPathSet)
	currWeight := p.Options[0].Weight
	// Go through sub policies
	for _, option := range p.Options {
		if currWeight > option.Weight && len(subPolicySet) > 0 {
			break
		}
		currWeight = option.Weight
		subPaths := option.Policy.Act(inputSet).(spathmeta.AppPathSet)
		for key, path := range subPaths {
			subPolicySet[key] = path
		}
	}
	return subPolicySet
}

// Option contains a weight and a policy and is used as a list item in Policy.Options
type Option struct {
	Weight int
	Policy *Policy
}

// Sequence is a list of path interfaces that a path should match
type Sequence []sciond.PathInterface

// NewSequence creates a new sequence from a list of string tokens
func NewSequence(tokens []string) (Sequence, error) {
	s := make(Sequence, 0)
	for _, token := range tokens {
		pi, err := sciond.NewPathInterface(token)
		if err != nil {
			return nil, err
		}
		s = append(s, pi)
	}
	return s, nil
}

// Eval evaluates the interface sequence list and returns the set of paths that match the list
func (s Sequence) Eval(inputSet spathmeta.AppPathSet) spathmeta.AppPathSet {
	if len(s) == 0 {
		return inputSet
	}

	resultSet := make(spathmeta.AppPathSet)
	for key, path := range inputSet {
		if pathMatches(path.Entry.Path.Interfaces, s) {
			resultSet[key] = path
		}
	}
	return resultSet
}

func pathMatches(pathInterfaces, matcherTokens []sciond.PathInterface) bool {
	// TODO(worxli): as long as *, ? and + are not implemented, these slices must have the
	// same length
	if len(pathInterfaces) != len(matcherTokens) {
		return false
	}
	for i := range pathInterfaces {
		if !spathmeta.PPWildcardEquals(matcherTokens[i], pathInterfaces[i]) {
			return false
		}
	}
	return true
}
