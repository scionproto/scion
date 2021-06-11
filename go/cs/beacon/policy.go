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
	"github.com/scionproto/scion/go/lib/serrors"
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
	DefaultBestSetSize = 20
	// DefaultCandidateSetSize is the default CandidateSetSize value.
	DefaultCandidateSetSize = 100
	// DefaultMaxHopsLength is the default MaxHopsLength value.
	DefaultMaxHopsLength = 10
	// DefaultMaxExpTime is the default MaxExpTime value.
	DefaultMaxExpTime = uint8(63)
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
		return serrors.New("Invalid policy type",
			"expected", PropPolicy, "actual", p.Prop.Type)
	}
	if p.UpReg.Type != UpRegPolicy {
		return serrors.New("Invalid policy type",
			"expected", UpRegPolicy, "actual", p.UpReg.Type)
	}
	if p.DownReg.Type != DownRegPolicy {
		return serrors.New("Invalid policy type",
			"expected", DownRegPolicy, "actual", p.DownReg.Type)
	}
	return nil
}

// Filter applies all filters and returns an error if all of them filter the
// beacon. If at least one does not filter, no error is returned.
func (p *Policies) Filter(beacon Beacon) error {
	var errors []error
	if err := p.Prop.Filter.Apply(beacon); err != nil {
		errors = append(errors, err)
	}
	if err := p.UpReg.Filter.Apply(beacon); err != nil {
		errors = append(errors, err)
	}
	if err := p.DownReg.Filter.Apply(beacon); err != nil {
		errors = append(errors, err)
	}
	if len(errors) == 3 {
		return serrors.New("Filtered by all policies", "errs", errors)
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
		return serrors.New("Invalid policy type",
			"expected", PropPolicy, "actual", p.Prop.Type)
	}
	if p.CoreReg.Type != CoreRegPolicy {
		return serrors.New("Invalid policy type",
			"expected", CoreRegPolicy, "actual", p.CoreReg.Type)
	}
	return nil
}

// Filter applies all filters and returns an error if all of them filter the
// beacon. If at least one does not filter, no error is returned.
func (p *CorePolicies) Filter(beacon Beacon) error {
	var errors []error
	if err := p.Prop.Filter.Apply(beacon); err != nil {
		errors = append(errors, err)
	}
	if err := p.CoreReg.Filter.Apply(beacon); err != nil {
		errors = append(errors, err)
	}
	if len(errors) == 2 {
		return serrors.New("Filtered by all policies", "errs", errors)
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
	// MaxExpTime indicates the maximum value for the expiration time when
	// extending the segment.
	MaxExpTime *uint8 `yaml:"MaxExpTime"`
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
	if p.MaxExpTime == nil {
		m := DefaultMaxExpTime
		p.MaxExpTime = &m
	}
	p.Filter.InitDefaults()
}

func (p *Policy) initDefaults(t PolicyType) error {
	p.InitDefaults()
	if p.Type != "" && p.Type != t {
		return serrors.New("Specified policy type does not match",
			"expected", t, "actual", p.Type)
	}
	p.Type = t
	return nil
}

// ParsePolicyYaml parses the policy in yaml format and initializes the default values.
func ParsePolicyYaml(b []byte, t PolicyType) (*Policy, error) {
	p := &Policy{}
	if err := yaml.UnmarshalStrict(b, p); err != nil {
		return nil, serrors.WrapStr("Unable to parse policy", err)
	}
	if err := p.initDefaults(t); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadPolicyFromYaml loads the policy from a yaml file and initializes the
// default values.
func LoadPolicyFromYaml(path string, t PolicyType) (*Policy, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, serrors.WrapStr("Unable to read policy file", err, "path", path)
	}
	return ParsePolicyYaml(b, t)
}

// Filter filters beacons.
type Filter struct {
	// MaxHopsLength is the maximum number of hops a segment can have.
	MaxHopsLength int `yaml:"MaxHopsLength"`
	// ASBlackList contains all ASes that may not appear in a segment.
	AsBlackList []addr.AS `yaml:"AsBlackList"`
	// IsdBlackList contains all ISD that may not appear in a segment.
	IsdBlackList []addr.ISD `yaml:"IsdBlackList"`
	// AllowIsdLoop indicates whether ISD loops should not be filtered.
	AllowIsdLoop *bool `yaml:"AllowIsdLoop"`
}

// InitDefaults initializes the default values for unset fields.
func (f *Filter) InitDefaults() {
	if f.MaxHopsLength == 0 {
		f.MaxHopsLength = DefaultMaxHopsLength
	}
	if f.AllowIsdLoop == nil {
		t := true
		f.AllowIsdLoop = &t
	}
}

// Apply returns an error if the beacon is filtered.
func (f Filter) Apply(beacon Beacon) error {
	if len(beacon.Segment.ASEntries) > f.MaxHopsLength {
		return serrors.New("MaxHopsLength exceeded", "max", f.MaxHopsLength,
			"actual", len(beacon.Segment.ASEntries))
	}
	hops := buildHops(beacon)
	if err := filterLoops(hops, *f.AllowIsdLoop); err != nil {
		return err
	}
	for _, ia := range hops {
		for _, as := range f.AsBlackList {
			if ia.A == as {
				return serrors.New("contains blocked AS", "isd_as", ia)
			}
		}
		for _, isd := range f.IsdBlackList {
			if ia.I == isd {
				return serrors.New("contains blocked ISD", "isd_as", ia)
			}
		}
	}
	return nil
}

// FilterLoop returns an error if the beacon contains an AS or ISD loop. If ISD
// loops are allowed, an error is returned only on AS loops.
func FilterLoop(beacon Beacon, next addr.IA, allowIsdLoop bool) error {
	hops := buildHops(beacon)
	if !next.IsZero() {
		hops = append(hops, next)
	}
	return filterLoops(hops, allowIsdLoop)
}

func buildHops(beacon Beacon) []addr.IA {
	hops := make([]addr.IA, 0, len(beacon.Segment.ASEntries)+1)
	for _, asEntry := range beacon.Segment.ASEntries {
		hops = append(hops, asEntry.Local)
	}
	return hops
}

func filterLoops(hops []addr.IA, allowIsdLoop bool) error {
	if ia := filterAsLoop(hops); !ia.IsZero() {
		return serrors.New("AS loop", "ia", ia)
	}
	if allowIsdLoop {
		return nil
	}
	if isd := filterIsdLoop(hops); isd != 0 {
		return serrors.New("ISD loop", "isd", isd)
	}
	return nil
}

func filterAsLoop(hops []addr.IA) addr.IA {
	seen := make(map[addr.IA]struct{})
	for _, ia := range hops {
		if _, ok := seen[ia]; ok {
			return ia
		}
		seen[ia] = struct{}{}
	}
	return addr.IA{}
}

func filterIsdLoop(hops []addr.IA) addr.ISD {
	seen := make(map[addr.ISD]struct{})
	var last addr.ISD
	for _, ia := range hops {
		if last == ia.I {
			continue
		}
		if _, ok := seen[ia.I]; ok {
			return ia.I
		}
		last = ia.I
		seen[ia.I] = struct{}{}
	}
	return 0
}
