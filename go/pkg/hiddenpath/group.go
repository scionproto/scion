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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
)

// GroupID is unique 64bit identification of the group.
type GroupID struct {
	OwnerAS addr.AS
	Suffix  uint16
}

func (id GroupID) String() string {
	return fmt.Sprintf("%s-%x", id.OwnerAS, id.Suffix)
}

func parseGroupID(s string) (GroupID, error) {
	v := strings.Replace(s, "_", ":", 2)
	parts := strings.Split(v, "-")
	if len(parts) != 2 {
		return GroupID{}, serrors.New("invalid group id format", "group_id", s)
	}

	ownerAS, err := addr.ASFromString(parts[0])
	if err != nil {
		return GroupID{}, err
	}
	suffix, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return GroupID{}, serrors.WrapStr("invalid group id suffix", err,
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
	// Version is the version of the configuration.
	Version uint
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

// ParseGroup processes a raw string and returns a hiddenpath group object.
// The raw string can be either json or yaml format.
func ParseGroup(raw []byte) (*Group, error) {
	type groupInfo struct {
		ID         string   `yaml:"group_id" json:"group_id"`
		Version    uint     `yaml:"version" json:"version"`
		Owner      string   `yaml:"owner" json:"owner"`
		Writers    []string `yaml:"writers" json:"writers"`
		Readers    []string `yaml:"readers" json:"readers"`
		Registries []string `yaml:"registries" json:"registries"`
	}

	info := &groupInfo{}
	if err1 := json.Unmarshal(raw, info); err1 != nil {
		if err2 := yaml.Unmarshal(raw, info); err2 != nil {
			return nil, serrors.New("unknown format, neither yml or json",
				"json", err1, "yml", err2)
		}
	}
	id, err := parseGroupID(info.ID)
	if err != nil {
		return nil, serrors.WrapStr("parsing group ID", err)

	}
	owner, err := addr.IAFromString(info.Owner)
	if err != nil {
		return nil, serrors.WrapStr("parsing owner", err)
	}

	ret := &Group{
		ID:         id,
		Version:    info.Version,
		Owner:      owner,
		Writers:    map[addr.IA]struct{}{},
		Readers:    map[addr.IA]struct{}{},
		Registries: map[addr.IA]struct{}{},
	}

	for _, w := range info.Writers {
		ia, err := addr.IAFromString(w)
		if err != nil {
			return nil, err
		}
		ret.Writers[ia] = struct{}{}
	}

	for _, r := range info.Readers {
		ia, err := addr.IAFromString(r)
		if err != nil {
			return nil, err
		}
		ret.Readers[ia] = struct{}{}
	}

	for _, r := range info.Registries {
		ia, err := addr.IAFromString(r)
		if err != nil {
			return nil, err
		}
		ret.Registries[ia] = struct{}{}
	}

	return ret, nil
}

func (g *Group) Validate() error {
	if g.ID == (GroupID{}) {
		return serrors.New("missing group id")
	}
	if g.Version == 0 {
		return serrors.New("invalid version", "version", 0)
	}
	if g.Owner.IsZero() {
		return serrors.New("missing owner")
	}
	if g.Owner.A != g.ID.OwnerAS {
		return serrors.New("owner mismatch",
			"owner_as", g.Owner.A, "group_id", g.ID.OwnerAS)
	}
	if len(g.Writers) == 0 {
		return serrors.New("writers section cannot be empty")
	}
	if len(g.Registries) == 0 {
		return serrors.New("registry section cannot be empty")
	}

	return nil
}
