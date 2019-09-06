// Copyright 2019 ETH Zurich
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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
)

// Parsing errors
const (
	// InvalidGroupIdFormat indicates an invalid GroupId format
	InvalidGroupIdFormat = "Invalid GroupId format"
	// InvalidGroupIdSuffix indicates an invalid GroupId suffix
	InvalidGroupIdSuffix = "Invalid GroupId suffix"
)

// Validation errors
const (
	// MissingGroupId indicates a missing GroupId
	MissingGroupId = "Missing GroupId"
	// InvalidVersion indicates a missing version
	InvalidVersion = "Invalid version"
	// MissingOwner indicates a missing Owner
	MissingOwner = "Missing Owner"
	// OwnerMismatch indicates a mismatch between Owner and GroupId.OwnerAS
	OwnerMismatch = "Owner mismatch"
	// EmptyWriters indicatres an empty Writer section
	EmptyWriters = "Writer section cannot be empty"
	// EmptyWriters indicatres an empty Writer section
	EmptyRegistries = "Registry section cannot be empty"
)

type GroupId struct {
	OwnerAS addr.AS
	Suffix  uint16
}

func (id GroupId) String() string {
	return fmt.Sprintf("%s-%x", id.OwnerAS, id.Suffix)
}

func (id *GroupId) UnmarshalText(data []byte) error {
	v := string(data)
	v = strings.Replace(v, "_", ":", 2)
	parts := strings.Split(v, "-")
	if len(parts) != 2 {
		return common.NewBasicError(InvalidGroupIdFormat, nil, "GroupId", v)
	}
	ownerAS, err := addr.ASFromString(parts[0])
	if err != nil {
		return err
	}
	suffix, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return common.NewBasicError(InvalidGroupIdSuffix, err, "Suffix", parts[1])
	}
	id.OwnerAS = ownerAS
	id.Suffix = uint16(suffix)
	return nil
}

func (id GroupId) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

func (id *GroupId) UnmarshalJSON(data []byte) (err error) {
	var v string
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
	return id.UnmarshalText([]byte(v))
}

func (id GroupId) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

// ToMsg returns id as Cerializable message suitable to be sent via messenger
func (id GroupId) ToMsg() *path_mgmt.HPGroupId {
	return &path_mgmt.HPGroupId{
		OwnerAS: id.OwnerAS,
		GroupId: id.Suffix,
	}
}

// IdFromMsg returns a GroupId from the Cerializable representation
func IdFromMsg(id *path_mgmt.HPGroupId) GroupId {
	return GroupId{
		OwnerAS: id.OwnerAS,
		Suffix:  id.GroupId,
	}
}

type Group struct {
	Id         GroupId `json:"GroupID"`
	Version    uint
	Owner      addr.IA
	Writers    []addr.IA
	Readers    []addr.IA
	Registries []addr.IA
}

func (g *Group) UnmarshalJSON(data []byte) (err error) {
	type groupAlias Group
	var v groupAlias
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
	if v.Id == (GroupId{}) {
		return common.NewBasicError(MissingGroupId, nil)
	}
	if v.Version == 0 {
		return common.NewBasicError(InvalidVersion, nil)
	}
	if v.Owner == (addr.IA{}) {
		return common.NewBasicError(MissingOwner, nil)
	}
	if v.Owner.A != v.Id.OwnerAS {
		return common.NewBasicError(OwnerMismatch, nil,
			"OwnerAS", v.Owner.A, "GroupId.OwnerAS", v.Id.OwnerAS)
	}
	if len(v.Writers) == 0 {
		return common.NewBasicError(EmptyWriters, nil)
	}
	if len(v.Registries) == 0 {
		return common.NewBasicError(EmptyRegistries, nil)
	}
	*g = Group(v)
	return nil
}

// HasWriter returns true if ia is a Writer of h
func (g *Group) HasWriter(ia addr.IA) bool {
	for _, w := range g.Writers {
		if w == ia {
			return true
		}
	}
	return false
}

// HasReader returns true if ia is a Reader of h
func (g *Group) HasReader(ia addr.IA) bool {
	for _, r := range g.Readers {
		if r == ia {
			return true
		}
	}
	return false
}

// HasRegistry returns true if ia is a Registry of h
func (g *Group) HasRegistry(ia addr.IA) bool {
	for _, r := range g.Registries {
		if r == ia {
			return true
		}
	}
	return false
}

// ToMsg returns h as Cerializable message suitable to be sent via messenger
func (g *Group) ToMsg() *path_mgmt.HPCfg {
	return &path_mgmt.HPCfg{
		GroupId:    g.Id.ToMsg(),
		Version:    uint32(g.Version),
		OwnerISD:   g.Owner.I,
		Writers:    toIAInt(g.Writers),
		Readers:    toIAInt(g.Readers),
		Registries: toIAInt(g.Registries),
	}
}

// GroupFromMsg returns a HPCfg from the Cerializable representation
func GroupFromMsg(m *path_mgmt.HPCfg) *Group {
	return &Group{
		Id:      IdFromMsg(m.GroupId),
		Version: uint(m.Version),
		Owner: addr.IA{
			I: m.OwnerISD,
			A: m.GroupId.OwnerAS,
		},
		Writers:    toIA(m.Writers),
		Readers:    toIA(m.Readers),
		Registries: toIA(m.Registries),
	}
}

func toIAInt(in []addr.IA) []addr.IAInt {
	out := make([]addr.IAInt, 0, len(in))
	for _, i := range in {
		out = append(out, i.IAInt())
	}
	return out
}

func toIA(in []addr.IAInt) []addr.IA {
	out := make([]addr.IA, 0, len(in))
	for _, i := range in {
		out = append(out, i.IA())
	}
	return out
}

// GroupIdSet is a set of hidden path GroupIds
type GroupIdSet map[GroupId]struct{}

// GroupIdsToSet converts a list of GroupIds to a GroupIdSet,
// ensuring no duplcates.
func GroupIdsToSet(ids ...GroupId) GroupIdSet {
	set := make(GroupIdSet, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}
