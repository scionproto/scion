package config

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
	// ErrOwnerMismatch indicates a mismatch between Owner and GroupId.OwnerAS
	ErrOwnerMismatch = "Owner mismatch"
	// ErrVersionMissing indicates a missing version
	ErrVersionMissing = "Version missing"
)

type HPCfg struct {
	GroupId    *path_mgmt.HPGroupId
	Version    uint
	Owner      addr.IA
	Writers    []addr.IA
	Readers    []addr.IA
	Registries []addr.IA
}

func (h *HPCfg) UnmarshalJSON(data []byte) (err error) {
	var v struct {
		GroupId    string `json:"GroupID"`
		Version    *uint
		Owner      addr.IA
		Writers    []addr.IA
		Readers    []addr.IA
		Registries []addr.IA
	}
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
	parts := strings.Split(v.GroupId, "-")
	if len(parts) != 2 {
		return common.NewBasicError(InvalidGroupIdFormat, nil, "GroupId", v.GroupId)
	}
	cfgOwnerAS, err := addr.ASFromString(parts[0])
	if err != nil {
		return err
	}
	id, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return common.NewBasicError(InvalidGroupIdSuffix, err, "suffix", parts[1])
	}
	if v.Version == nil {
		return common.NewBasicError(ErrVersionMissing, nil)
	}
	if v.Owner.A != cfgOwnerAS {
		return common.NewBasicError(ErrOwnerMismatch, nil,
			"OwnerAS", v.Owner.A, "GroupId.OwnerAS", cfgOwnerAS)
	}
	h.GroupId = &path_mgmt.HPGroupId{}
	h.GroupId.OwnerAS = cfgOwnerAS
	h.GroupId.GroupId = uint16(id)
	h.Version = *v.Version
	h.Owner = v.Owner
	h.Writers = v.Writers
	h.Readers = v.Readers
	h.Registries = v.Registries

	return nil
}

func (h *HPCfg) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		GroupId    string `json:"GroupID"`
		Version    uint
		Owner      addr.IA
		Writers    []addr.IA
		Readers    []addr.IA
		Registries []addr.IA
	}{
		GroupId:    fmt.Sprintf("%s-%x", h.GroupId.OwnerAS, h.GroupId.GroupId),
		Version:    h.Version,
		Owner:      h.Owner,
		Writers:    h.Writers,
		Readers:    h.Readers,
		Registries: h.Registries,
	})
}

// HasWriter returns true if ia is a Writer of h
func (h *HPCfg) HasWriter(ia addr.IA) bool {
	for _, w := range h.Writers {
		if w == ia {
			return true
		}
	}
	return false
}

// HasReader returns true if ia is a Reader of h
func (h *HPCfg) HasReader(ia addr.IA) bool {
	for _, r := range h.Readers {
		if r == ia {
			return true
		}
	}
	return false
}

// HasRegistry returns true if ia is a Registry of h
func (h *HPCfg) HasRegistry(ia addr.IA) bool {
	for _, r := range h.Registries {
		if r == ia {
			return true
		}
	}
	return false
}

// ToMsg retruns h as Cerializable message suitable to be sent via messenger
func (h *HPCfg) ToMsg() *path_mgmt.HPCfg {
	writers := toIAInt(h.Writers)
	readers := toIAInt(h.Readers)
	registries := toIAInt(h.Registries)
	return &path_mgmt.HPCfg{
		GroupId:    h.GroupId,
		Version:    uint32(h.Version),
		OwnerISD:   h.Owner.I,
		Writers:    writers,
		Readers:    readers,
		Registries: registries,
	}
}

// FromMsg retruns a HPCfg from the Cerializable representation
func FromMsg(m *path_mgmt.HPCfg) *HPCfg {
	writers := toIA(m.Writers)
	readers := toIA(m.Readers)
	registries := toIA(m.Registries)
	return &HPCfg{
		GroupId: m.GroupId,
		Version: uint(m.Version),
		Owner: addr.IA{
			I: m.OwnerISD,
			A: m.GroupId.OwnerAS,
		},
		Writers:    writers,
		Readers:    readers,
		Registries: registries,
	}
}

func toIAInt(in []addr.IA) []addr.IAInt {
	var out []addr.IAInt
	for _, i := range in {
		out = append(out, i.IAInt())
	}
	return out
}

func toIA(in []addr.IAInt) []addr.IA {
	var out []addr.IA
	for _, i := range in {
		out = append(out, i.IA())
	}
	return out
}
