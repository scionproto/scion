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
// Currently implemented: ACL, Sequence, Extends and Options.
//
// A policy has an Act() method that takes an AppPathSet and returns a filtered AppPathSet
package pathpol

import (
	"fmt"
	"sort"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

// ExtPolicy is an extending policy, it may have a list of policies it extends
type ExtPolicy struct {
	Extends []string `json:",omitempty"`
	*Policy
}

// PolicyMap is a container for Policies, keyed by their unique name. PolicyMap
// can be used to marshal Policies to JSON. Unmarshaling back to PolicyMap is
// guaranteed to yield an object that is identical to the initial one.
type PolicyMap map[string]*ExtPolicy

// Policy is a compiled path policy object, all extended policies have been merged.
type Policy struct {
	Name     string    `json:"-"`
	ACL      *ACL      `json:",omitempty"`
	Sequence *Sequence `json:",omitempty"`
	Options  []Option  `json:",omitempty"`
}

// NewPolicy creates a Policy and sorts its Options
func NewPolicy(name string, acl *ACL, sequence *Sequence, options []Option) *Policy {
	policy := &Policy{Name: name, ACL: acl, Sequence: sequence, Options: options}
	// Sort Options by weight, descending
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
	if p.Sequence != nil {
		resultSet = p.Sequence.Eval(resultSet)
	}
	// Filter on sub policies
	if len(p.Options) > 0 {
		resultSet = p.evalOptions(resultSet)
	}
	return resultSet
}

// PolicyFromExtPolicy creates a Policy from an extending Policy and the extended policies
func PolicyFromExtPolicy(extPolicy *ExtPolicy, extended []*ExtPolicy) (*Policy, error) {
	policy := extPolicy.Policy
	if policy == nil {
		policy = &Policy{}
	}
	// Apply all extended policies
	if err := policy.applyExtended(extPolicy.Extends, extended); err != nil {
		return nil, err
	}
	return policy, nil
}

// applyExtended adds attributes of extended policies to the extending policy if they are not
// already set
func (p *Policy) applyExtended(extends []string, exPolicies []*ExtPolicy) error {
	// TODO(worxli): Prevent circular policies.
	// traverse in reverse s.t. last entry of the list has precedence
	for i := len(extends) - 1; i >= 0; i-- {
		var policy *Policy
		// Find extended policy
		for _, exPol := range exPolicies {
			if exPol.Name == extends[i] {
				var err error
				if policy, err = PolicyFromExtPolicy(exPol, exPolicies); err != nil {
					return err
				}
			}
		}
		if policy == nil {
			return common.NewBasicError(
				fmt.Sprintf("Extended policy '%s' could not be found", extends[i]), nil)
		}
		// Replace ACL
		if p.ACL == nil && policy.ACL != nil {
			p.ACL = policy.ACL
		}
		// Replace Options
		if len(p.Options) == 0 {
			p.Options = policy.Options
		}
		// Replace Sequence
		if p.Sequence == nil {
			p.Sequence = policy.Sequence
		}
	}
	return nil
}

// evalOptions evaluates the options of a policy and returns the pathSet that matches the option
// with the highest weight
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
