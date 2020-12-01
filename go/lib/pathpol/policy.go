// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
// A policy has Filter() method that takes a slice of paths and returns a
// filtered slice of paths.
package pathpol

import (
	"sort"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

// ExtPolicy is an extending policy, it may have a list of policies it extends
type ExtPolicy struct {
	Extends []string `json:"extends,omitempty"`
	*Policy
}

// PolicyMap is a container for Policies, keyed by their unique name. PolicyMap
// can be used to marshal Policies to JSON. Unmarshaling back to PolicyMap is
// guaranteed to yield an object that is identical to the initial one.
type PolicyMap map[string]*ExtPolicy

// FilterOptions contains options for filtering.
type FilterOptions struct {
	// IgnoreSequence can be used to ignore the sequence part of policies.
	IgnoreSequence bool
}

// Policy is a compiled path policy object, all extended policies have been merged.
type Policy struct {
	Name     string    `json:"-"`
	ACL      *ACL      `json:"acl,omitempty"`
	Sequence *Sequence `json:"sequence,omitempty"`
	Options  []Option  `json:"options,omitempty"`
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

// Filter filters the paths according to the policy.
func (p *Policy) Filter(paths []snet.Path) []snet.Path {
	return p.FilterOpt(paths, FilterOptions{})
}

// FilterOpt filters the path set according to the policy with the given
// options.
func (p *Policy) FilterOpt(paths []snet.Path, opts FilterOptions) []snet.Path {
	if p == nil {
		return paths
	}
	result := p.ACL.Eval(paths)
	if p.Sequence != nil && !opts.IgnoreSequence {
		result = p.Sequence.Eval(result)
	}
	// Filter on sub policies
	if len(p.Options) > 0 {
		result = p.evalOptions(result, opts)
	}
	return result
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
			return serrors.New("Extended policy could not be found",
				"policy", extends[i])
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
func (p *Policy) evalOptions(paths []snet.Path, opts FilterOptions) []snet.Path {
	subPolicySet := make(map[snet.PathFingerprint]struct{})
	currWeight := p.Options[0].Weight
	// Go through sub policies
	for _, option := range p.Options {
		if currWeight > option.Weight && len(subPolicySet) > 0 {
			break
		}
		currWeight = option.Weight
		subPaths := option.Policy.FilterOpt(paths, opts)
		for _, path := range subPaths {
			subPolicySet[snet.Fingerprint(path)] = struct{}{}
		}
	}
	result := []snet.Path{}
	for _, path := range paths {
		if _, ok := subPolicySet[snet.Fingerprint(path)]; ok {
			result = append(result, path)
		}
	}
	return result
}

// Option contains a weight and a policy and is used as a list item in Policy.Options
type Option struct {
	Weight int        `json:"weight"`
	Policy *ExtPolicy `json:"policy"`
}
