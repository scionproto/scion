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

	"github.com/netsec-ethz/scion/go/lib/util"
)

type InfoEcho struct {
	Id  uint16
	Seq uint16
}

func InfoEchoFromRaw(b util.RawBytes) (*InfoEcho, *util.Error) {
	e := &InfoEcho{}
	if err := restruct.Unpack(b, order, e); err != nil {
		return nil, util.NewError("Failed to unpack SCMP ECHO info", "err", err)
	}
	return e, nil
}

type InfoPktSize struct {
	Size uint16
	MTU  uint16
}

func InfoPktSizeFromRaw(b util.RawBytes) (*InfoPktSize, *util.Error) {
	p := &InfoPktSize{}
	if err := restruct.Unpack(b, order, p); err != nil {
		return nil, util.NewError("Failed to unpack SCMP Pkt Size info", "err", err)
	}
	return p, nil
}

type InfoPathOffsets struct {
	InfoF   uint16
	HopF    uint16
	IfID    uint16
	Ingress bool
}

func InfoPathOffsetsFromRaw(b util.RawBytes) (*InfoPathOffsets, *util.Error) {
	p := &InfoPathOffsets{}
	if err := restruct.Unpack(b, order, p); err != nil {
		return nil, util.NewError("Failed to unpack SCMP Path Offsets info", "err", err)
	}
	return p, nil
}

func (p *InfoPathOffsets) String() string {
	return fmt.Sprintf("InfoF=%d HopF=%d IfID=%d Ingress=%v", p.InfoF, p.HopF, p.IfID, p.Ingress)
}

type InfoRevocation struct {
	InfoPathOffsets
	RevToken util.RawBytes
}

func InfoRevocationFromRaw(b util.RawBytes) (*InfoRevocation, *util.Error) {
	p := &InfoRevocation{}
	if err := restruct.Unpack(b, order, &p.InfoPathOffsets); err != nil {
		return nil, util.NewError("Failed to unpack SCMP Revocation info", "err", err)
	}
	p.RevToken = b[8:]
	return p, nil
}

func (r *InfoRevocation) String() string {
	return fmt.Sprintf("InfoF=%d HopF=%d IfID=%d Ingress=%v RevToken=%v",
		r.InfoF, r.HopF, r.IfID, r.Ingress, r.RevToken)
}
