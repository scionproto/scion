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

type Policy struct {
	name    string
	acl     *ACL
	list    []string
	conds   map[string]string // bw, mtu, lat etc.
	extends []*Policy
	options []PolicyOption
}

func NewPolicy(name string, acl *ACL, list []string, extends []*Policy,
	options []PolicyOption) *Policy {
	return &Policy{
		name:    name,
		acl:     acl,
		list:    list,
		extends: extends,
		options: options}
}

// Act filters the path set accoring the policy
// Currently implemented: ACL, List, Options
// See planned features in doc/PathPolicy.md
func (p *Policy) Act(values interface{}) interface{} {
	inputSet := values.(spathmeta.AppPathSet)
	// Apply all extended policies
	p.applyExtended()
	// Filter on ACL
	resultSet := p.evalPolicyACL(inputSet)
	// Filter on list
	if len(p.list) > 0 {
		resultSet = p.evalPolicyList(resultSet)
	}
	// Filter on sub policies
	if len(p.options) > 0 {
		resultSet = p.evalOptions(resultSet)
	}
	return resultSet
}

func (p *Policy) GetName() string {
	return p.name
}

func (p *Policy) SetName(name string) {
	p.name = name
}

func (p *Policy) Type() string {
	return "Policy"
}

// applyExtended addes attributes of extended policies to the extending policy if they are not
// already set
func (p *Policy) applyExtended() {
	// traverse in reverse s.t. last entry of the list has precedence
	for i := len(p.extends) - 1; i >= 0; i-- {
		policy := p.extends[i]
		policy.applyExtended()

		// Replace ACL
		if p.acl == nil && policy.acl != nil {
			p.acl = policy.acl
		}
		// Replace options
		if (p.options == nil || len(p.options) == 0) &&
			(policy.options != nil && len(policy.options) > 0) {
			p.options = policy.options
		}
		// Replace list
		if len(p.list) == 0 && len(policy.list) > 0 {
			p.list = policy.list
		}
		// Replace usual attributes
		for key := range policy.conds {
			if _, ok := p.conds[key]; !ok {
				p.conds[key] = policy.conds[key]
			}
		}
	}
	// all sub-policies have been set, remove them
	p.extends = nil
}

// evalPolicyACL returns the set of paths that match the ACL
func (p *Policy) evalPolicyACL(inputSet spathmeta.AppPathSet) spathmeta.AppPathSet {
	resultSet := make(spathmeta.AppPathSet)
	for key, path := range inputSet {
		// Check ACL
		if p.acl.Eval(path) {
			resultSet[key] = path
		}
	}
	return resultSet
}

// evalPolicyList evaluates the interface sequence list and returns the set of paths that match
// the list
func (p *Policy) evalPolicyList(inputSet spathmeta.AppPathSet) spathmeta.AppPathSet {
	resultSet := make(spathmeta.AppPathSet)
	for key, path := range inputSet {
		ifaces := path.Entry.Path.Interfaces
		if len(ifaces) != len(p.list) {
			continue
		}
		matched := true
		for i := range ifaces {
			if p.list[i] == ".." {
				continue
			}
			pi, err := sciond.NewPathInterface(p.list[i])
			if err != nil {
				panic(err)
			}
			if !ppWildcardEquals(&ifaces[i], &pi) {
				matched = false
				break
			}
		}
		if matched {
			resultSet[key] = path
		}
	}
	return resultSet
}

// evalOptions evaluates the options of a policy and returns the pathSet that matches the option
// with the heighest weight
func (p *Policy) evalOptions(inputSet spathmeta.AppPathSet) spathmeta.AppPathSet {
	subPolicySet := make(spathmeta.AppPathSet)
	maxWeight := 0
	// Go through sub polcies
	for _, option := range p.options {
		subPolicies := option.policy.Act(inputSet).(spathmeta.AppPathSet)
		// Use only new policies if weight is larger than current weight
		if option.weight > maxWeight && len(subPolicies) > 0 {
			subPolicySet = subPolicies
			maxWeight = option.weight
		} else
		// If weight is the same we return both policy sets
		if option.weight == maxWeight {
			for key, path := range subPolicies {
				subPolicySet[key] = path
			}
		}
	}
	return subPolicySet
}

type PolicyOption struct {
	weight int
	policy *Policy
}
