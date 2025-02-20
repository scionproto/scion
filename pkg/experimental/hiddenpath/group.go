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

package hiddenpath

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/config"
)

// GroupID is unique 64bit identification of the group.
type GroupID struct {
	OwnerAS addr.AS
	Suffix  uint16
}

// GroupIDFromUint64 creates the group ID from the uint64 representation.
func GroupIDFromUint64(id uint64) GroupID {
	return GroupID{
		OwnerAS: addr.AS(id >> 16),
		Suffix:  uint16(id),
	}
}

// ToUint64 returns the uint64 representation of the group ID.
func (id GroupID) ToUint64() uint64 {
	return uint64(id.OwnerAS)<<16 | uint64(id.Suffix)
}

func (id GroupID) String() string {
	return fmt.Sprintf("%s-%x", id.OwnerAS, id.Suffix)
}

// ParseGroupID parses the string representation of the group ID.
func ParseGroupID(s string) (GroupID, error) {
	v := strings.Replace(s, "_", ":", 2)
	parts := strings.Split(v, "-")
	if len(parts) != 2 {
		return GroupID{}, serrors.New("invalid group id format", "group_id", s)
	}

	ownerAS, err := addr.ParseAS(parts[0])
	if err != nil {
		return GroupID{}, err
	}
	suffix, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return GroupID{}, serrors.Wrap("invalid group id suffix", err,
			"suffix", parts[1], "group_id", s)

	}

	return GroupID{
		OwnerAS: ownerAS,
		Suffix:  uint16(suffix),
	}, nil
}

// Group is a group of ASes that share hidden path information.
type Group struct {
	// ID is a 64-bit unique identifier of the group. It is the concatenation of
	// the owner AS number and a hex encoded 16-bit suffix.
	ID GroupID
	// Owner is the AS ID of the owner of the hidden path group. The Owner AS is
	// responsible for maintaining the hidden path group configuration and
	// distributing it to all entities that require it.
	Owner addr.IA
	// Writers contains all ASes in the group that are allowed to register hidden
	// paths.
	Writers map[addr.IA]struct{}
	// Readers contains all ASes in the group which are allowed to read hidden
	// path information.
	Readers map[addr.IA]struct{}
	// Registries contains all ASes in the group at which Writers register hidden
	// paths.
	Registries map[addr.IA]struct{}
}

// Validate validates the group.
func (g *Group) Validate() error {
	if g.ID.ToUint64() == 0 {
		return serrors.New("missing group id")
	}
	if g.Owner.IsZero() {
		return serrors.New("missing owner")
	}
	if g.Owner.AS() != g.ID.OwnerAS {
		return serrors.New("owner mismatch",
			"owner_as", g.Owner.AS(), "group_id", g.ID.OwnerAS)
	}
	if len(g.Writers) == 0 {
		return serrors.New("writers section cannot be empty")
	}
	if len(g.Registries) == 0 {
		return serrors.New("registry section cannot be empty")
	}

	return nil
}

func (g *Group) GetRegistries() []addr.IA {
	var ret []addr.IA
	for k := range g.Registries {
		ret = append(ret, k)
	}
	return ret
}

// Roles indicates roles in a hidden path group(s).
type Roles struct {
	Owner    bool
	Registry bool
	Reader   bool
	Writer   bool
}

// None returns true if no role is set.
func (r Roles) None() bool {
	return !r.Owner && !r.Registry && !r.Reader && !r.Writer
}

// Groups is a list of hidden path groups.
type Groups map[GroupID]*Group

// Validate validates all groups in the map.
func (g Groups) Validate() error {
	for _, group := range g {
		if err := group.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalYAML implements the yaml unmarshaller for the Groups type.
func (g Groups) UnmarshalYAML(unmarshal func(any) error) error {
	yg := &registrationPolicyInfo{}
	if err := unmarshal(&yg); err != nil {
		return serrors.Wrap("unmarshaling YAML", err)
	}
	if len(yg.Groups) == 0 {
		return nil
	}
	groups, err := parseGroups(yg.Groups)
	if err != nil {
		return err
	}
	for id, group := range groups {
		g[id] = group
	}
	return nil
}

// MarshalYAML implements yaml marshalling.
func (g Groups) MarshalYAML() (any, error) {
	return &registrationPolicyInfo{
		Groups: marshalGroups(g),
	}, nil
}

// LoadHiddenPathGroups loads the hiddenpath groups configuration file.
func LoadHiddenPathGroups(location string) (Groups, error) {
	ret := make(Groups)
	if location == "" {
		return nil, nil
	}
	c, err := config.LoadResource(location)
	if err != nil {
		return nil, serrors.Wrap("reading", err, "location", location)
	}
	defer c.Close()
	if err := yaml.NewDecoder(c).Decode(&ret); err != nil {
		return nil, serrors.Wrap("parsing", err, "location", location)
	}
	if err := ret.Validate(); err != nil {
		return nil, serrors.Wrap("validating", err, "file", c)
	}
	return ret, nil
}

// Roles returns the roles the given ISD-AS has in this set of groups.
func (g Groups) Roles(ia addr.IA) Roles {
	r := Roles{}
	inSet := func(ia addr.IA, set map[addr.IA]struct{}) bool {
		_, ok := set[ia]
		return ok
	}
	for _, group := range g {
		r.Owner = r.Owner || ia.Equal(group.Owner)
		r.Registry = r.Registry || inSet(ia, group.Registries)
		r.Reader = r.Reader || inSet(ia, group.Readers)
		r.Writer = r.Writer || inSet(ia, group.Writers)
	}
	return r
}

type groupInfo struct {
	Owner      string   `yaml:"owner,omitempty"`
	Writers    []string `yaml:"writers,omitempty"`
	Readers    []string `yaml:"readers,omitempty"`
	Registries []string `yaml:"registries,omitempty"`
}

func parseGroups(groups map[string]*groupInfo) (Groups, error) {
	result := make(Groups)
	for rawID, rawGroup := range groups {
		id, err := ParseGroupID(rawID)
		if err != nil {
			return nil, serrors.Wrap("parsing group ID", err)
		}
		owner, err := addr.ParseIA(rawGroup.Owner)
		if err != nil {
			return nil, serrors.Wrap("parsing owner", err, "group_id", id)
		}
		writers, err := stringsToIASet(rawGroup.Writers)
		if err != nil {
			return nil, serrors.Wrap("parsing writer", err)
		}
		readers, err := stringsToIASet(rawGroup.Readers)
		if err != nil {
			return nil, serrors.Wrap("parsing readers", err)
		}
		registries, err := stringsToIASet(rawGroup.Registries)
		if err != nil {
			return nil, serrors.Wrap("parsing registries", err)
		}
		result[id] = &Group{
			ID:         id,
			Owner:      owner,
			Writers:    writers,
			Readers:    readers,
			Registries: registries,
		}
	}
	return result, nil
}

func marshalGroups(groups Groups) map[string]*groupInfo {
	result := make(map[string]*groupInfo, len(groups))
	for id, group := range groups {
		result[id.String()] = &groupInfo{
			Owner:      group.Owner.String(),
			Writers:    iaSetToStrings(group.Writers),
			Readers:    iaSetToStrings(group.Readers),
			Registries: iaSetToStrings(group.Registries),
		}
	}
	return result
}

func iaSetToStrings(ias map[addr.IA]struct{}) []string {
	result := make([]string, 0, len(ias))
	for ia := range ias {
		result = append(result, ia.String())
	}
	// make consistent output.
	sort.Strings(result)
	return result
}

func stringsToIASet(rawIAs []string) (map[addr.IA]struct{}, error) {
	result := make(map[addr.IA]struct{})
	for _, rawIA := range rawIAs {
		ia, err := addr.ParseIA(rawIA)
		if err != nil {
			return nil, err
		}
		result[ia] = struct{}{}
	}
	return result, nil
}
