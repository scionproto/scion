package hpGroup

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
	// OwnerMismatch indicates a mismatch between Owner and GroupId.OwnerAS
	OwnerMismatch = "Owner mismatch"
	// InvalidVersion indicates a missing version
	InvalidVersion = "Invalid version"
)

type Id struct {
	OwnerAS addr.AS
	Suffix  uint16
}

func (id *Id) UnmarshalJSON(data []byte) (err error) {
	var v string
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
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
		return common.NewBasicError(InvalidGroupIdSuffix, err, "suffix", parts[1])
	}
	id.OwnerAS = ownerAS
	id.Suffix = uint16(suffix)
	return nil
}

func (id *Id) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%s-%x", id.OwnerAS, id.Suffix))
}

type Group struct {
	GroupId    *Id `json:"GroupID"`
	Version    uint
	Owner      addr.IA
	Writers    []addr.IA
	Readers    []addr.IA
	Registries []addr.IA
}

func (h *Group) UnmarshalJSON(data []byte) (err error) {
	var v struct {
		GroupId    *Id
		Version    uint
		Owner      addr.IA
		Writers    []addr.IA
		Readers    []addr.IA
		Registries []addr.IA
	}
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
	if v.Version == 0 {
		return common.NewBasicError(InvalidVersion, nil)
	}
	if v.Owner.A != v.GroupId.OwnerAS {
		return common.NewBasicError(OwnerMismatch, nil,
			"OwnerAS", v.Owner.A, "GroupId.OwnerAS", v.GroupId.OwnerAS)
	}
	h.GroupId = v.GroupId
	h.Version = v.Version
	h.Owner = v.Owner
	h.Writers = v.Writers
	h.Readers = v.Readers
	h.Registries = v.Registries

	return nil
}

// IsWriter returns true if ia is a Writer of h
func (h *Group) IsWriter(ia addr.IA) bool {
	for _, w := range h.Writers {
		if w == ia {
			return true
		}
	}
	return false
}

// IsReader returns true if ia is a Reader of h
func (h *Group) IsReader(ia addr.IA) bool {
	for _, r := range h.Readers {
		if r == ia {
			return true
		}
	}
	return false
}

// IsRegistry returns true if ia is a Registry of h
func (h *Group) IsRegistry(ia addr.IA) bool {
	for _, r := range h.Registries {
		if r == ia {
			return true
		}
	}
	return false
}

// ToMsg retruns h as Cerializable message suitable to be sent via messenger
func (h *Group) ToMsg() *path_mgmt.HPCfg {
	return &path_mgmt.HPCfg{
		GroupId: &path_mgmt.HPGroupId{
			OwnerAS: h.GroupId.OwnerAS,
			GroupId: h.GroupId.Suffix,
		},
		Version:    uint32(h.Version),
		OwnerISD:   h.Owner.I,
		Writers:    toIAInt(h.Writers),
		Readers:    toIAInt(h.Readers),
		Registries: toIAInt(h.Registries),
	}
}

// FromMsg retruns a HPCfg from the Cerializable representation
func FromMsg(m *path_mgmt.HPCfg) *Group {
	return &Group{
		GroupId: &Id{
			OwnerAS: m.GroupId.OwnerAS,
			Suffix:  m.GroupId.GroupId,
		},
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
