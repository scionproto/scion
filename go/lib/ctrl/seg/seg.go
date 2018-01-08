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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*PathSegment)(nil)

type PathSegment struct {
	RawSData     common.RawBytes        `capnp:"sdata"`
	SData        *PathSegmentSignedData `capnp:"-"`
	RawASEntries []*proto.SignedBlobS   `capnp:"asEntries"`
	ASEntries    []*ASEntry             `capnp:"-"`
	id           common.RawBytes
}

func NewSeg(infoF *spath.InfoField) (*PathSegment, error) {
	pss := newPathSegmentSignedData(infoF)
	rawPss, err := proto.PackRoot(pss)
	if err != nil {
		return nil, err
	}
	ps := &PathSegment{RawSData: rawPss, SData: pss}
	return ps, nil
}

func NewSegFromRaw(b common.RawBytes) (*PathSegment, error) {
	ps := &PathSegment{}
	err := proto.ParseFromRaw(ps, ps.ProtoId(), b)
	if err != nil {
		return nil, err
	}
	ps.SData, err = NewPathSegmentSignedDataFromRaw(ps.RawSData)
	if err != nil {
		return nil, err
	}
	for i := range ps.RawASEntries {
		ase, err := newASEntryFromRaw(ps.RawASEntries[i].Blob)
		if err != nil {
			return nil, err
		}
		ps.ASEntries = append(ps.ASEntries, ase)
	}
	return ps, nil
}

func (ps *PathSegment) ID() (common.RawBytes, error) {
	if ps.id == nil {
		h := sha256.New()
		for _, ase := range ps.ASEntries {
			binary.Write(h, common.Order, ase.RawIA)
			hopf, err := ase.HopEntries[0].HopField()
			if err != nil {
				return nil, err
			}
			binary.Write(h, common.Order, hopf.Ingress)
			binary.Write(h, common.Order, hopf.Egress)
		}
		ps.id = h.Sum(nil)
	}
	return ps.id, nil
}

func (ps *PathSegment) InfoF() (*spath.InfoField, error) {
	return ps.SData.InfoF()
}

func (ps *PathSegment) AddASEntry(ase *ASEntry, signType proto.SignType,
	signSrc common.RawBytes) error {
	rawASE, err := ase.Pack()
	if err != nil {
		return err
	}
	ps.RawASEntries = append(ps.RawASEntries, &proto.SignedBlobS{
		Blob: rawASE,
		Sign: proto.NewSignS(signType, signSrc),
	})
	ps.ASEntries = append(ps.ASEntries, ase)
	ps.id = nil
	return nil
}

func (ps *PathSegment) SignLastASEntry(key common.RawBytes) error {
	idx := ps.MaxAEIdx()
	packed, err := ps.sigPack(idx)
	if err != nil {
		return err
	}
	return ps.RawASEntries[idx].Sign.SignAndSet(key, packed)
}

func (ps *PathSegment) VerifyASEntry(key common.RawBytes, idx int) error {
	packed, err := ps.sigPack(idx)
	if err != nil {
		return err
	}
	return ps.RawASEntries[idx].Sign.Verify(key, packed)
}

func (ps *PathSegment) sigPack(idx int) (common.RawBytes, error) {
	err := ps.validateIdx(idx)
	if err != nil {
		return nil, err
	}
	data := append(common.RawBytes(nil), ps.RawSData...)
	for i := 0; i < idx; i++ {
		data = append(data, ps.RawASEntries[i].Pack()...)
	}
	data = append(data, ps.RawASEntries[idx].Blob...)
	return data, nil
}

func (ps *PathSegment) MaxAEIdx() int {
	return len(ps.RawASEntries) - 1
}

func (ps *PathSegment) validateIdx(idx int) error {
	if idx < 0 || idx > ps.MaxAEIdx() {
		return common.NewBasicError("Invalid ASEntry index", nil,
			"min", 0, "max", ps.MaxAEIdx(), "actual", idx)
	}
	return nil
}

func (ps *PathSegment) Write(b common.RawBytes) (int, error) {
	return proto.WriteRoot(ps, b)
}

func (ps *PathSegment) Pack() (common.RawBytes, error) {
	return proto.PackRoot(ps)
}

func (ps *PathSegment) ProtoId() proto.ProtoIdType {
	return proto.PathSegment_TypeID
}

func (ps *PathSegment) String() string {
	desc := []string{}
	if id, err := ps.ID(); err != nil {
		desc = append(desc, fmt.Sprintf("ID error: %s", err))
	} else {
		desc = append(desc, id.String())
	}
	info, _ := ps.InfoF()
	desc = append(desc, info.Timestamp().UTC().Format(common.TimeFmt))
	hops_desc := []string{}
	for _, ase := range ps.ASEntries {
		hop_entry := ase.HopEntries[0]
		hop, err := hop_entry.HopField()
		if err != nil {
			hops_desc = append(hops_desc, err.Error())
			continue
		}
		hop_desc := []string{}
		if hop.Ingress > 0 {
			hop_desc = append(hop_desc, fmt.Sprintf("%v ", hop.Ingress))
		}
		hop_desc = append(hop_desc, ase.IA().String())
		if hop.Egress > 0 {
			hop_desc = append(hop_desc, fmt.Sprintf(" %v", hop.Egress))
		}
		hops_desc = append(hops_desc, strings.Join(hop_desc, ""))
	}
	// TODO(shitz): Add extensions.
	desc = append(desc, strings.Join(hops_desc, ">"))
	return strings.Join(desc, "")
}
