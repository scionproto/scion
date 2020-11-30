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

package hiddenpath

import (
	"sort"

	"github.com/scionproto/scion/go/lib/serrors"
)

// InterfacePolicy defines the registration policy for an ingress interface.
type InterfacePolicy struct {
	// The policy for registering the segment publicly.
	Public bool
	// The policies for the different hidden path groups.
	Groups map[GroupID]*Group
}

// RegistrationPolicy describes the policy for registering segments. The map is
// keyed by ingress interface ID.
type RegistrationPolicy map[uint64]InterfacePolicy

// Validate validates the registration policy.
func (p RegistrationPolicy) Validate() error {
	for ifID, p := range p {
		for id, group := range p.Groups {
			if err := group.Validate(); err != nil {
				return serrors.WrapStr("validating group", err, "group_id", id, "interface", ifID)
			}
		}
	}
	return nil
}

// MarshalYAML implements the yaml marshaller interface.
func (p RegistrationPolicy) MarshalYAML() (interface{}, error) {
	collectedGroups := make(Groups)
	policies := make(map[uint64][]string, len(p))
	for ifID, ip := range p {
		for id, group := range ip.Groups {
			collectedGroups[id] = group
			policies[ifID] = append(policies[ifID], id.String())
		}
		if ip.Public {
			policies[ifID] = append(policies[ifID], "public")
		}
		sort.Strings(policies[ifID])
	}
	return &registrationPolicyInfo{
		Groups:   marshalGroups(collectedGroups),
		Policies: policies,
	}, nil
}

// UnmarshalYAML implements YAML unmarshaling for the registration policy type.
func (p RegistrationPolicy) UnmarshalYAML(unmarshal func(interface{}) error) error {
	rawPolicy := &registrationPolicyInfo{}
	if err := unmarshal(&rawPolicy); err != nil {
		return serrors.WrapStr("parsing yaml", err)
	}
	groups, err := parseGroups(rawPolicy.Groups)
	if err != nil {
		return err
	}
	for ifID, groupIDs := range rawPolicy.Policies {
		pol := InterfacePolicy{
			Groups: make(map[GroupID]*Group),
		}
		for _, groupID := range groupIDs {
			if groupID == "public" {
				pol.Public = true
				continue
			}
			id, err := ParseGroupID(groupID)
			if err != nil {
				return serrors.WrapStr("parsing group ID", err)
			}
			group, ok := groups[id]
			if !ok {
				return serrors.New("referring to unknown group", "group_id", id)
			}
			pol.Groups[id] = group
		}
		p[ifID] = pol
	}
	return nil
}

type registrationPolicyInfo struct {
	Groups   map[string]*groupInfo `yaml:"groups,omitempty"`
	Policies map[uint64][]string   `yaml:"registration_policy_per_interface,omitempty"`
}
