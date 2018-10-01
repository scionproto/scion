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

package pathpcy

import (
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
	ACL      *ACL
	Sequence *Sequence
	Extends  []*Policy
	Options  []Option
}

// Act filters the path set according the policy
func (p *Policy) Act(values interface{}) interface{} {
	inputSet := values.(spathmeta.AppPathSet)
	// Apply all extended policies
	p.applyExtended()
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
		policy.applyExtended()

		// Replace ACL
		if p.ACL == nil && policy.ACL != nil {
			p.ACL = policy.ACL
		}
		// Replace options
		if (p.Options == nil || len(p.Options) == 0) &&
			(policy.Options != nil && len(policy.Options) > 0) {
			p.Options = policy.Options
		}
		// Replace Sequence
		if p.Sequence.Length() == 0 && policy.Sequence.Length() > 0 {
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
	maxWeight := 0
	// Go through sub policies
	for _, option := range p.Options {
		subPaths := option.Policy.Act(inputSet).(spathmeta.AppPathSet)
		// Use only new policies if weight is larger than current weight
		if option.Weight > maxWeight && len(subPaths) > 0 {
			subPolicySet = subPaths
			maxWeight = option.Weight
		} else {
			// If weight is the same we return both policy sets
			if option.Weight == maxWeight {
				for key, path := range subPaths {
					subPolicySet[key] = path
				}
			}
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
type Sequence struct {
	tokens []sciond.PathInterface
}

// NewSequence creates a new sequence from a list of string tokens
func NewSequence(tokens []string) *Sequence {
	list := &Sequence{}
	for _, token := range tokens {
		list.tokens = append(list.tokens, pathInterfaceFromToken(token))
	}
	return list
}

func pathInterfaceFromToken(item string) sciond.PathInterface {
	if item == ".." {
		return sciond.PathInterface{}
	}
	pi, err := sciond.NewPathInterface(item)
	if err != nil {
		panic(err)
	}
	return pi
}

func (sequence *Sequence) Length() int {
	if sequence == nil {
		return 0
	}
	return len(sequence.tokens)
}

// Eval evaluates the interface sequence list and returns the set of paths that match
// the list
func (sequence *Sequence) Eval(inputSet spathmeta.AppPathSet) spathmeta.AppPathSet {
	if sequence == nil || len(sequence.tokens) == 0 {
		return inputSet
	}

	resultSet := make(spathmeta.AppPathSet)
	for key, path := range inputSet {
		if pathMatches(path.Entry.Path.Interfaces, sequence.tokens) {
			resultSet[key] = path
		}
	}
	return resultSet
}

func pathMatches(pathInterfaces, matcherTokens []sciond.PathInterface) bool {
	if len(pathInterfaces) != len(matcherTokens) {
		return false
	}
	for i := range pathInterfaces {
		if !spathmeta.PPWildcardEquals(&matcherTokens[i], &pathInterfaces[i]) {
			return false
		}
	}
	return true
}
