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

package pathpol

// PolicyMap is a container for Policies, keyed by their unique name. PolicyMap
// can be used to marshal Policies to JSON. Unmarshaling back to PolicyMap is
// guaranteed to yield an object that is identical to the initial one.
type PolicyMap map[string]*ExtPolicy

// ExtPolicy is an extending policy, it may have a list of policies it extends
type ExtPolicy struct {
	Name     string      `json:"-"`
	ACL      *ACL        `json:"acl,omitempty"`
	Sequence *Sequence   `json:"sequence,omitempty"`
	Options  []ExtOption `json:"options,omitempty"`
	// Extends are the names of policies this policy extends.
	Extends []string `json:"extends,omitempty"`
}

// ExtOption is an option for extended policies.
type ExtOption struct {
	Weight int        `json:"weight"`
	Policy *ExtPolicy `json:"policy"`
}
