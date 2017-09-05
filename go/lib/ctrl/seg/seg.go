// Copyright 2017 ETH Zurich
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

// This file contains the Go representation of a Path Segment

package seg

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*PathSegment)(nil)

type PathSegment struct {
	RawInfo   []byte `capnp:"info"`
	IfID      uint64
	ASEntries []*ASEntry `capnp:"asms"`
	Exts      struct {
		Sibra []byte `capnp:"-"` // Omit SIBRA extension for now.
	}
}

func NewFromRaw(b common.RawBytes) (*PathSegment, error) {
	ps := &PathSegment{}
	return ps, proto.ParseFromRaw(ps, ps.ProtoId(), b)
}

func (ps *PathSegment) ID() (common.RawBytes, error) {
	h := sha256.New()
	for _, as := range ps.ASEntries {
		binary.Write(h, common.Order, as.RawIA)
		hopf, err := as.HopEntries[0].HopField()
		if err != nil {
			return nil, err
		}
		binary.Write(h, common.Order, hopf.Ingress)
		binary.Write(h, common.Order, hopf.Egress)
	}
	return h.Sum(nil), nil
}

func (ps *PathSegment) Info() (*spath.InfoField, error) {
	return spath.InfoFFromRaw(ps.RawInfo)
}

func (ps *PathSegment) ProtoId() proto.ProtoIdType {
	return proto.PathSegment_TypeID
}

func (ps *PathSegment) Write(b common.RawBytes) (int, error) {
	return proto.WriteRoot(ps, b)
}

func (ps *PathSegment) Pack() (common.RawBytes, error) {
	return proto.PackRoot(ps)
}

func (ps *PathSegment) String() string {
	desc := []string{}
	if id, err := ps.ID(); err != nil {
		desc = append(desc, fmt.Sprintf("ID error: %s", err))
	} else {
		desc = append(desc, id.String())
	}
	info, _ := ps.Info()
	desc = append(desc, info.Timestamp().UTC().Format(common.TimeFmt))
	hops_desc := []string{}
	for _, as := range ps.ASEntries {
		hop := as.HopEntries[0]
		hop_desc := []string{}
		if hop.InIF > 0 {
			hop_desc = append(hop_desc, fmt.Sprintf("%v ", hop.InIF))
		}
		hop_desc = append(hop_desc, as.IA().String())
		if hop.OutIF > 0 {
			hop_desc = append(hop_desc, fmt.Sprintf(" %v", hop.OutIF))
		}
		hops_desc = append(hops_desc, strings.Join(hop_desc, ""))
	}
	// TODO(shitz): Add extensions.
	desc = append(desc, strings.Join(hops_desc, ">"))
	return strings.Join(desc, "")
}

type Meta struct {
	Type    Type
	Segment PathSegment `capnp:"pcb"`
}

func (m *Meta) String() string {
	return fmt.Sprintf("Type: %v, Segment: %v", m.Type, m.Segment)
}

type Type uint8

const (
	UpSegment   Type = 0
	DownSegment Type = 1
	CoreSegment Type = 2
)

func (t Type) String() string {
	switch t {
	case UpSegment:
		return "UP"
	case DownSegment:
		return "DOWN"
	case CoreSegment:
		return "CORE"
	}
	return fmt.Sprintf("UNKNOWN (%d)", t)
}
