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
	"encoding/binary"
	"fmt"

	"gopkg.in/restruct.v1"

	"github.com/scionproto/scion/go/lib/common"
)

type Meta struct {
	InfoLen    uint8
	CmnHdrLen  uint8
	AddrHdrLen uint8
	PathHdrLen uint8
	ExtHdrsLen uint8
	L4HdrLen   uint8
	L4Proto    common.L4ProtocolType
}

const (
	MetaLen = 8
)

func MetaFromRaw(b []byte) (*Meta, error) {
	m := &Meta{}
	if err := restruct.Unpack(b, binary.BigEndian, m); err != nil {
		return nil, common.NewBasicError("Failed to unpack SCMP Metadata", err)
	}
	return m, nil
}

func (m *Meta) Copy() *Meta {
	return &Meta{
		InfoLen: m.InfoLen, CmnHdrLen: m.CmnHdrLen, AddrHdrLen: m.AddrHdrLen,
		PathHdrLen: m.PathHdrLen, ExtHdrsLen: m.ExtHdrsLen,
		L4HdrLen: m.L4HdrLen, L4Proto: m.L4Proto,
	}
}

func (m *Meta) Write(b common.RawBytes) error {
	out, err := restruct.Pack(common.Order, m)
	if err != nil {
		return common.NewBasicError("Error packing SCMP Metadata", err)
	}
	copy(b, out)
	return nil
}

func (m *Meta) String() string {
	return fmt.Sprintf(
		"Info=%d CmnHdr=%d AddrHdr=%d PathHdr=%d ExtHdrs=%d L4Hdr=%d L4Proto=%v",
		m.InfoLen, m.CmnHdrLen, m.AddrHdrLen, m.PathHdrLen, m.ExtHdrsLen, m.L4HdrLen, m.L4Proto,
	)
}
