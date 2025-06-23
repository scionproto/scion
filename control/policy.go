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

package control

import (
	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/config"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
)

// LoadCorePolicies loads the policies for beaconing in a core CS.
func LoadCorePolicies(cfg config.Policies) (beacon.CorePolicies, error) {
	var err error
	var policies beacon.CorePolicies
	if policies.Prop, err = loadPolicy(cfg.Propagation, beacon.PropPolicy); err != nil {
		return policies, err
	}
	if policies.CoreReg, err = loadPolicy(cfg.CoreRegistration, beacon.CoreRegPolicy); err != nil {
		return policies, err
	}
	return policies, nil
}

// LoadNonCorePolicies loads the policies for beaconing in a non-core CS.
func LoadNonCorePolicies(cfg config.Policies) (beacon.Policies, error) {
	var err error
	var policies beacon.Policies
	if policies.Prop, err = loadPolicy(cfg.Propagation, beacon.PropPolicy); err != nil {
		return policies, err
	}
	if policies.UpReg, err = loadPolicy(cfg.UpRegistration, beacon.UpRegPolicy); err != nil {
		return policies, err
	}
	if policies.DownReg, err = loadPolicy(cfg.DownRegistration, beacon.DownRegPolicy); err != nil {
		return policies, err
	}
	return policies, nil
}

func loadPolicy(fn string, t beacon.PolicyType) (beacon.Policy, error) {
	var policy beacon.Policy
	if fn != "" {
		p, err := beacon.LoadPolicyFromYaml(fn, t)
		if err != nil {
			return policy, serrors.Wrap("loading beaconing policy", err, "file", fn, "type", t)
		}
		if err := p.Validate(); err != nil {
			return policy, serrors.Wrap("validating beaconing policy", err, "file", fn, "type", t)
		}
		policy = *p
	}
	policy.InitDefaults()
	return policy, nil
}

// SegmentTypeFromRegPolicyType converts a registration beacon.PolicyType to a segment.Type.
//
// The second return value is false iff the conversion fails. This happens if the given policy
// type is not a registration policy, e.g., PropPolicy.
func SegmentTypeFromRegPolicyType(policyType beacon.PolicyType) (seg.Type, bool) {
	switch policyType {
	case beacon.UpRegPolicy:
		return seg.TypeUp, true
	case beacon.DownRegPolicy:
		return seg.TypeDown, true
	case beacon.CoreRegPolicy:
		return seg.TypeCore, true
	// Not a registration policy
	default:
		return 0, false
	}
}
