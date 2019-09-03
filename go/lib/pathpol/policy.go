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
// A policy has an Act() method that takes an AppPathSet and returns a filtered AppPathSet
package pathpol

import (
	"sort"

	"github.com/scionproto/scion/go/lib/common"
)

// FilterOptions contains options for filtering.
type FilterOptions struct {
	// IgnoreSequence can be used to ignore the sequence part of policies.
	IgnoreSequence bool
}

// Policy is a compiled path policy object, all extended policies have been merged.
type Policy struct {
	Name     string
	ACL      *ACL
	Sequence *Sequence
	Options  []Option
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

// Filter filters the path set according to the policy.
func (p *Policy) Filter(paths PathSet) PathSet {
	return p.FilterOpt(paths, FilterOptions{})
}

// FilterOpt filters the path set according to the policy with the given
// options.
func (p *Policy) FilterOpt(paths PathSet, opts FilterOptions) PathSet {
	if p == nil {
		return paths
	}
	resultSet := p.ACL.Eval(paths)
	if p.Sequence != nil && !opts.IgnoreSequence {
		resultSet = p.Sequence.Eval(resultSet)
	}
	// Filter on sub policies
	if len(p.Options) > 0 {
		resultSet = p.evalOptions(resultSet, opts)
	}
	return resultSet
}

// PolicyFromExtPolicy creates a Policy from an extending Policy and the
// extended policies. It resolves all extended policies also the ones in the
// options.
func PolicyFromExtPolicy(extPolicy *ExtPolicy, extended []*ExtPolicy) (*Policy, error) {
	policy := &Policy{
		ACL:      extPolicy.ACL,
		Sequence: extPolicy.Sequence,
	}
	var err error
	if policy.Options, err = convertOpts(extPolicy, extended); err != nil {
		return nil, err
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
			return common.NewBasicError("Extended policy could not be found", nil,
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
func (p *Policy) evalOptions(inputSet PathSet, opts FilterOptions) PathSet {
	subPolicySet := make(PathSet)
	currWeight := p.Options[0].Weight
	// Go through sub policies
	for _, option := range p.Options {
		if currWeight > option.Weight && len(subPolicySet) > 0 {
			break
		}
		currWeight = option.Weight
		subPaths := option.Policy.FilterOpt(inputSet, opts)
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

// OptionFromExtOption creates an Option from an extended Option.
func OptionFromExtOption(extOpt ExtOption, extended []*ExtPolicy) (Option, error) {
	pol, err := PolicyFromExtPolicy(extOpt.Policy, extended)
	if err != nil {
		return Option{}, err
	}
	opt := Option{
		Weight: extOpt.Weight,
		Policy: pol,
	}
	return opt, nil
}

func convertOpts(extPolicy *ExtPolicy, extended []*ExtPolicy) ([]Option, error) {
	if len(extPolicy.Options) == 0 {
		return nil, nil
	}
	opts := make([]Option, 0, len(extPolicy.Options))
	for _, extOpt := range extPolicy.Options {
		opt, err := OptionFromExtOption(extOpt, extended)
		if err != nil {
			return nil, err
		}
		opts = append(opts, opt)
	}
	return opts, nil
}
