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
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/ptr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/path/pathpol"
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

// RegPolicyType is the registration policy type, which is a subset of PolicyType.
type RegPolicyType string

const (
	// RegPolicyTypeUp is the registration policy type for up segments.
	RegPolicyTypeUp RegPolicyType = RegPolicyType(UpRegPolicy)
	// RegPolicyTypeDown is the registration policy type for down segments.
	RegPolicyTypeDown RegPolicyType = RegPolicyType(DownRegPolicy)
	// RegPolicyTypeCore is the registration policy type for core segments.
	RegPolicyTypeCore RegPolicyType = RegPolicyType(CoreRegPolicy)
)

// ToRegPolicyType converts a PolicyType to a RegPolicyType if it is a registration policy type.
// The second return value indicates whether the conversion was successful.
func (p PolicyType) ToRegPolicyType() (RegPolicyType, bool) {
	switch p {
	case UpRegPolicy:
		return RegPolicyTypeUp, true
	case DownRegPolicy:
		return RegPolicyTypeDown, true
	case CoreRegPolicy:
		return RegPolicyTypeCore, true
	default:
		return "", false
	}
}

// SegmentType returns the segment type associated with this registration policy.
func (p RegPolicyType) SegmentType() segment.Type {
	switch p {
	case RegPolicyTypeUp:
		return segment.TypeUp
	case RegPolicyTypeDown:
		return segment.TypeDown
	case RegPolicyTypeCore:
		return segment.TypeCore
	default:
		panic("unreachable: invalid registration policy type")
	}
}

// ToPolicyType converts a RegPolicyType to a generic PolicyType.
func (p RegPolicyType) ToPolicyType() PolicyType {
	switch p {
	case RegPolicyTypeUp:
		return UpRegPolicy
	case RegPolicyTypeDown:
		return DownRegPolicy
	case RegPolicyTypeCore:
		return CoreRegPolicy
	default:
		panic("unreachable: invalid registration policy type")
	}
}

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
	// RegistrationPolicies contains the registration policies for this policy.
	RegistrationPolicies []RegistrationPolicy `yaml:"RegistrationPolicies"`
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
	for _, regPolicy := range p.RegistrationPolicies {
		regPolicy.InitDefaults()
	}
	p.Filter.InitDefaults()
}

// Validate checks that the policy does not have duplicate registration policy names.
func (p *Policy) Validate() error {
	for i := range len(p.RegistrationPolicies) {
		for j := i + 1; j < len(p.RegistrationPolicies); j++ {
			if p.RegistrationPolicies[i].Name == p.RegistrationPolicies[j].Name {
				return serrors.New("duplicate registration policy names found",
					"name", p.RegistrationPolicies[i].Name)
			}
		}
	}
	return nil
}

func (p *Policy) initDefaults(t PolicyType) {
	p.InitDefaults()
	if p.Type == "" {
		p.Type = t
	}
}

// RegistrationPolicy contains the parameters for a registration policy.
// A registration policy is used to register segments with a registrar.
type RegistrationPolicy struct {
	Name         string                    `yaml:"Name"`
	Description  string                    `yaml:"Description"`
	Matcher      RegistrationPolicyMatcher `yaml:"Matcher"`
	Plugin       string                    `yaml:"Plugin"`
	PluginConfig map[string]any            `yaml:"PluginConfig"`
}

// InitDefaults initializes the default values for unset fields in the registration policy.
func (p *RegistrationPolicy) InitDefaults() {
}

// beaconAsPath implements snet.Path with respect to a Beacon.
type beaconAsPath struct {
	beacon Beacon
	snet.Path
}

var _ snet.Path = (*beaconAsPath)(nil)

// wrapBeacon wraps a Beacon into a beaconAsPath which "trivially" implements snet.Path.
// Since snet.Path is set to nil, calling the methods that are not explicitly overwritten
// will panic!
func wrapBeacon(beacon Beacon) *beaconAsPath {
	return &beaconAsPath{
		beacon: beacon,
		Path:   nil,
	}
}

// Metadata returns the metadata of the beacon.
// It only sets the PathMetadata.Interfaces field.
func (b *beaconAsPath) Metadata() *snet.PathMetadata {
	md := snet.PathMetadata{}
	md.Interfaces = make([]snet.PathInterface, 0)
	for i, entry := range b.beacon.Segment.ASEntries {
		// For the AS entries that are not the first, add the interface with ingress interface.
		if i > 0 {
			md.Interfaces = append(md.Interfaces, snet.PathInterface{
				IA: entry.Local,
				ID: iface.ID(entry.HopEntry.HopField.ConsIngress),
			})
		}
		// For the AS entries that are not the last, add the interface with egress interface.
		if i < len(b.beacon.Segment.ASEntries)-1 {
			md.Interfaces = append(md.Interfaces, snet.PathInterface{
				IA: entry.Next,
				ID: iface.ID(entry.HopEntry.HopField.ConsEgress),
			})
		}
	}
	return &md
}

// RegistrationPolicyMatcher contains the matching criteria for a registration policy.
type RegistrationPolicyMatcher struct {
	Sequence *pathpol.Sequence `yaml:"Sequence"`
	ACL      *pathpol.ACL      `yaml:"ACL"`
}

// Match returns true iff the given beacon matches the registration policy matcher.
// Note that an empty matcher matches everything.
func (m *RegistrationPolicyMatcher) Match(beacon Beacon) bool {
	if m.Sequence != nil && len(m.Sequence.Eval([]snet.Path{wrapBeacon(beacon)})) == 0 {
		return false
	}
	if m.ACL != nil && len(m.ACL.Eval([]snet.Path{wrapBeacon(beacon)})) == 0 {
		return false
	}
	return true
}

// ParsePolicyYaml parses the policy in yaml format and initializes the default values.
func ParsePolicyYaml(r io.Reader, t PolicyType) (*Policy, error) {
	d := yaml.NewDecoder(r)
	d.KnownFields(true)
	p := &Policy{}
	if err := d.Decode(p); err != nil {
		return nil, serrors.Wrap("Unable to parse policy", err)
	}
	if p.Type != "" && p.Type != t {
		return nil, serrors.New("specified policy type does not match",
			"expected", t, "actual", p.Type)
	}
	p.initDefaults(t)
	return p, nil
}

// LoadPolicyFromYaml loads the policy from a yaml file and initializes the
// default values.
func LoadPolicyFromYaml(path string, t PolicyType) (*Policy, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0o644)
	if err != nil {
		return nil, serrors.Wrap("Unable to open policy file", err, "path", path)
	}
	defer func() { _ = f.Close() }()
	return ParsePolicyYaml(f, t)
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
		f.AllowIsdLoop = ptr.To(true)
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
			if ia.AS() == as {
				return serrors.New("contains blocked AS", "isd_as", ia)
			}
		}
		for _, isd := range f.IsdBlackList {
			if ia.ISD() == isd {
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
	return 0
}

func filterIsdLoop(hops []addr.IA) addr.ISD {
	seen := make(map[addr.ISD]struct{})
	var last addr.ISD
	for _, ia := range hops {
		if last == ia.ISD() {
			continue
		}
		if _, ok := seen[ia.ISD()]; ok {
			return ia.ISD()
		}
		last = ia.ISD()
		seen[ia.ISD()] = struct{}{}
	}
	return 0
}
