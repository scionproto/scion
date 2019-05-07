// Copyright 2019 Anapaya Systems
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

package beacon

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// PolicyType is the policy type.
type PolicyType string

const (
	// PropPolicy is the propagation policy.
	PropPolicy PolicyType = "Propagation"
	// UpRegPolicy is the registration policy for up segments.
	UpRegPolicy PolicyType = "UpSegmentRegistration"
	// DownRegPolicy is the registration policy for down segments.
	DownRegPolicy PolicyType = "DownSegmentRegistration"
	// CoreRegPolicy is the registration policy for core segments.
	CoreRegPolicy PolicyType = "CoreSegmentRegistration"
)

const (
	// DefaultBestSetSize is the default BestSetSize value.
	DefaultBestSetSize = 5
	// DefaultCandidateSetSize is the default CandidateSetSize value.
	DefaultCandidateSetSize = 100
	// DefaultMaxHopsLength is the default MaxHopsLength value.
	DefaultMaxHopsLength = 10
)

// Policies keeps track of all policies for a non-core beacon store.
type Policies struct {
	// Prop is the propagation policy.
	Prop Policy
	// UpReg is the up segment policy.
	UpReg Policy
	// DownReg is the down segment policy.
	DownReg Policy
}

// InitDefaults sets the defaults for all policies.
func (p *Policies) InitDefaults() {
	p.Prop.initDefaults(PropPolicy)
	p.UpReg.initDefaults(UpRegPolicy)
	p.DownReg.initDefaults(DownRegPolicy)
}

// Validate checks that each policy is of the correct type.
func (p *Policies) Validate() error {
	if p.Prop.Type != PropPolicy {
		return common.NewBasicError("Invalid policy type", nil,
			"expected", PropPolicy, "actual", p.Prop.Type)
	}
	if p.UpReg.Type != UpRegPolicy {
		return common.NewBasicError("Invalid policy type", nil,
			"expected", UpRegPolicy, "actual", p.UpReg.Type)
	}
	if p.DownReg.Type != DownRegPolicy {
		return common.NewBasicError("Invalid policy type", nil,
			"expected", DownRegPolicy, "actual", p.DownReg.Type)
	}
	return nil
}

// Usage returns the allowed usage of the beacon based on all available
// policies. For missing policies, the usage is not permitted.
func (p *Policies) Usage(beacon Beacon) Usage {
	var u Usage
	if p.Prop.Filter.Apply(beacon) == nil {
		u |= UsageProp
	}
	if p.UpReg.Filter.Apply(beacon) == nil {
		u |= UsageUpReg
	}
	if p.DownReg.Filter.Apply(beacon) == nil {
		u |= UsageDownReg
	}
	return u
}

// CorePolicies keeps track of all policies for a core beacon store.
type CorePolicies struct {
	// Prop is the propagation policy.
	Prop Policy
	// CoreReg is the core segment policy.
	CoreReg Policy
}

// InitDefaults sets the defaults for all policies.
func (p *CorePolicies) InitDefaults() {
	p.Prop.initDefaults(PropPolicy)
	p.CoreReg.initDefaults(CoreRegPolicy)
}

// Validate checks that each policy is of the correct type.
func (p *CorePolicies) Validate() error {
	if p.Prop.Type != PropPolicy {
		return common.NewBasicError("Invalid policy type", nil,
			"expected", PropPolicy, "actual", p.Prop.Type)
	}
	if p.CoreReg.Type != CoreRegPolicy {
		return common.NewBasicError("Invalid policy type", nil,
			"expected", CoreRegPolicy, "actual", p.CoreReg.Type)
	}
	return nil
}

// Usage returns the allowed usage of the beacon based on all available
// policies. For missing policies, the usage is not permitted.
func (p *CorePolicies) Usage(beacon Beacon) Usage {
	var u Usage
	if p.Prop.Filter.Apply(beacon) == nil {
		u |= UsageProp
	}
	if p.CoreReg.Filter.Apply(beacon) == nil {
		u |= UsageCoreReg
	}
	return u
}

// Policy contains the policy parameters when handling beacons.
type Policy struct {
	// BestSetSize is the number of segments to propagate or register.
	BestSetSize int `yaml:"BestSetSize"`
	// CandidateSetSize is the number of segments to consider for
	// selection.
	CandidateSetSize int `yaml:"CandidateSetSize"`
	// Filter is the filter applied to segments.
	Filter Filter `yaml:"Filter"`
	// Type is the policy type.
	Type PolicyType `yaml:"Type"`
}

// InitDefaults initializes the default values for unset fields.
func (p *Policy) InitDefaults() {
	if p.BestSetSize == 0 {
		p.BestSetSize = DefaultBestSetSize
	}
	if p.CandidateSetSize == 0 {
		p.CandidateSetSize = DefaultCandidateSetSize
	}
	p.Filter.InitDefaults()
}

func (p *Policy) initDefaults(t PolicyType) {
	p.InitDefaults()
	if p.Type == "" {
		p.Type = t
	}
}

// ParseYaml parses the policy in yaml format and initializes the default values.
func ParseYaml(b common.RawBytes, t PolicyType) (*Policy, error) {
	p := &Policy{}
	if err := yaml.Unmarshal(b, p); err != nil {
		return nil, common.NewBasicError("Unable to parse policy", err)
	}
	p.InitDefaults()
	if p.Type == "" {
		p.Type = t
	}
	if p.Type != t {
		return nil, common.NewBasicError("Specified policy type does not match", nil,
			"expected", t, "actual", p.Type)
	}
	return p, nil
}

// LoadFromYaml loads the policy from a yaml file and initializes the
// default values.
func LoadFromYaml(path string, t PolicyType) (*Policy, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, common.NewBasicError("Unable to read policy file", err, "path", path)
	}
	return ParseYaml(b, t)
}

// Filter filters beacons.
type Filter struct {
	// MaxHopsLength is the maximum number of hops a segment can have.
	MaxHopsLength int `yaml:"MaxHopsLength"`
	// ASBlackList contains all ASes that may not appear in a segment.
	AsBlackList []addr.AS `yaml:"AsBlackList"`
	// IsdBlackList contains all ISD that may not appear in a segment.
	IsdBlackList []addr.ISD `yaml:"IsdBlackList"`
}

// InitDefaults initializes the default values for unset fields.
func (f *Filter) InitDefaults() {
	if f.MaxHopsLength == 0 {
		f.MaxHopsLength = DefaultMaxHopsLength
	}
}

// Apply returns an error if the beacon is filtered.
func (f Filter) Apply(beacon Beacon) error {
	if len(beacon.Segment.ASEntries) > f.MaxHopsLength {
		return common.NewBasicError("MaxHopsLength exceeded", nil, "max", f.MaxHopsLength,
			"actual", len(beacon.Segment.ASEntries))
	}
	for _, entry := range beacon.Segment.ASEntries {
		ia := entry.IA()
		for _, as := range f.AsBlackList {
			if ia.A == as {
				return common.NewBasicError("Contains blacklisted AS", nil, "ia", ia)
			}
		}
		for _, isd := range f.IsdBlackList {
			if ia.I == isd {
				return common.NewBasicError("Contains blacklisted ISD", nil, "isd", ia)
			}
		}
	}
	return nil
}
