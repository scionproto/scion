// Copyright 2016 ETH Zurich
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

package scmp

import (
	"fmt"

	//log "github.com/inconshreveable/log15"
	"gopkg.in/restruct.v1"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type Info interface {
	fmt.Stringer
	Copy() Info
	Len() int
	Write(b common.RawBytes) (int, error)
}

var _ Info = (*InfoString)(nil)

type InfoString string

func (s InfoString) Copy() Info {
	// Strings are immutable, so no need to actually copy.
	return s
}

func (s InfoString) Len() int {
	l := 2 + len(s)
	return l + util.CalcPadding(l, common.LineLen)
}

func (s InfoString) Write(b common.RawBytes) (int, error) {
	common.Order.PutUint16(b, uint16(len(s)))
	copy(b[:2], s)
	return util.FillPadding(b, 2+len(s), common.LineLen), nil
}

func (s InfoString) String() string {
	return string(s)
}

var _ Info = (*InfoEcho)(nil)

type InfoEcho struct {
	Id  uint16
	Seq uint16
}

func InfoEchoFromRaw(b common.RawBytes) (*InfoEcho, error) {
	e := &InfoEcho{}
	if err := restruct.Unpack(b, common.Order, e); err != nil {
		return nil, common.NewCError("Failed to unpack SCMP ECHO info", "err", err)
	}
	return e, nil
}

func (e *InfoEcho) Copy() Info {
	return &InfoEcho{Id: e.Id, Seq: e.Seq}
}

func (e *InfoEcho) Len() int {
	l := 4
	return l + util.CalcPadding(l, common.LineLen)
}

func (e *InfoEcho) Write(b common.RawBytes) (int, error) {
	common.Order.PutUint16(b[0:], e.Id)
	common.Order.PutUint16(b[2:], e.Seq)
	return util.FillPadding(b, 4, common.LineLen), nil
}

func (e *InfoEcho) String() string {
	return fmt.Sprintf("Id=%v Seq=%v", e.Id, e.Seq)
}

var _ Info = (*InfoPktSize)(nil)

type InfoPktSize struct {
	Size uint16
	MTU  uint16
}

func InfoPktSizeFromRaw(b common.RawBytes) (*InfoPktSize, error) {
	p := &InfoPktSize{}
	if err := restruct.Unpack(b, common.Order, p); err != nil {
		return nil, common.NewCError("Failed to unpack SCMP Pkt Size info", "err", err)
	}
	return p, nil
}

func (p *InfoPktSize) Copy() Info {
	return &InfoPktSize{Size: p.Size, MTU: p.MTU}
}

func (p *InfoPktSize) Len() int {
	l := 4
	return l + util.CalcPadding(l, common.LineLen)
}

func (p *InfoPktSize) Write(b common.RawBytes) (int, error) {
	common.Order.PutUint16(b[0:], p.Size)
	common.Order.PutUint16(b[2:], p.MTU)
	return util.FillPadding(b, 4, common.LineLen), nil
}

func (p *InfoPktSize) String() string {
	return fmt.Sprintf("Size=%v MTU=%v", p.Size, p.MTU)
}

var _ Info = (*InfoPathOffsets)(nil)

type InfoPathOffsets struct {
	InfoF   uint16
	HopF    uint16
	IfID    uint16
	Ingress bool
}

func InfoPathOffsetsFromRaw(b common.RawBytes) (*InfoPathOffsets, error) {
	p := &InfoPathOffsets{}
	if err := restruct.Unpack(b, common.Order, p); err != nil {
		return nil, common.NewCError("Failed to unpack SCMP Path Offsets info", "err", err)
	}
	return p, nil
}

func (p *InfoPathOffsets) Copy() Info {
	return &InfoPathOffsets{InfoF: p.InfoF, HopF: p.HopF, IfID: p.IfID, Ingress: p.Ingress}
}

func (p *InfoPathOffsets) Len() int {
	l := 7
	return l + util.CalcPadding(l, common.LineLen)
}

func (p *InfoPathOffsets) Write(b common.RawBytes) (int, error) {
	common.Order.PutUint16(b[0:], p.InfoF)
	common.Order.PutUint16(b[2:], p.HopF)
	common.Order.PutUint16(b[4:], p.IfID)
	if p.Ingress {
		b[6] = 1
	} else {
		b[6] = 0
	}
	return util.FillPadding(b, 7, common.LineLen), nil
}

func (p *InfoPathOffsets) String() string {
	return fmt.Sprintf("InfoF=%d HopF=%d IfID=%d Ingress=%v", p.InfoF, p.HopF, p.IfID, p.Ingress)
}

var _ Info = (*InfoRevocation)(nil)

type InfoRevocation struct {
	*InfoPathOffsets
	RevToken common.RawBytes
}

func NewInfoRevocation(infoF, hopF, ifID uint16, ingress bool,
	revToken common.RawBytes) *InfoRevocation {
	return &InfoRevocation{
		InfoPathOffsets: &InfoPathOffsets{InfoF: infoF, HopF: hopF, IfID: ifID, Ingress: ingress},
		RevToken:        revToken,
	}
}

func InfoRevocationFromRaw(b common.RawBytes) (*InfoRevocation, error) {
	p := &InfoRevocation{InfoPathOffsets: &InfoPathOffsets{}}
	if err := restruct.Unpack(b, common.Order, &p.InfoPathOffsets); err != nil {
		return nil, common.NewCError("Failed to unpack SCMP Revocation info", "err", err)
	}
	p.RevToken = b[8:]
	return p, nil
}
func (r *InfoRevocation) Copy() Info {
	return &InfoRevocation{
		r.InfoPathOffsets.Copy().(*InfoPathOffsets),
		append(common.RawBytes(nil), r.RevToken...),
	}
}

func (r *InfoRevocation) Len() int {
	l := r.InfoPathOffsets.Len() + len(r.RevToken)
	return l + util.CalcPadding(l, common.LineLen)
}

func (r *InfoRevocation) Write(b common.RawBytes) (int, error) {
	count, err := r.InfoPathOffsets.Write(b)
	if err != nil {
		return 0, err
	}
	count += copy(b[count:], r.RevToken)
	return util.FillPadding(b, count, common.LineLen), nil
}

func (r *InfoRevocation) String() string {
	return fmt.Sprintf("InfoF=%d HopF=%d IfID=%d Ingress=%v RevToken=%v",
		r.InfoF, r.HopF, r.IfID, r.Ingress, r.RevToken)
}

var _ Info = (*InfoExtIdx)(nil)

type InfoExtIdx struct {
	Idx uint8
}

func InfoExtIdxFromRaw(b common.RawBytes) (*InfoExtIdx, error) {
	return &InfoExtIdx{Idx: b[0]}, nil
}

func (e *InfoExtIdx) Copy() Info {
	return &InfoExtIdx{Idx: e.Idx}
}

func (r *InfoExtIdx) Len() int {
	return 1 + util.CalcPadding(1, common.LineLen)
}

func (e *InfoExtIdx) Write(b common.RawBytes) (int, error) {
	b[0] = e.Idx
	return util.FillPadding(b, 1, common.LineLen), nil
}

func (e *InfoExtIdx) String() string {
	return fmt.Sprintf("Idx=%v", e.Idx)
}
