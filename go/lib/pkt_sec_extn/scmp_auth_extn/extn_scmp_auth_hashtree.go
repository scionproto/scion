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

//    HashTree:
//
//    0B       1        2        3        4        5        6        7
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x05  | Height |            Order         |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                               Signature (8 lines)                     |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                               Hashes (height * 2)                     |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//

package scmp_auth_extn

import (
	"bytes"
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/pkt_sec_extn"
)

var _ common.Extension = (*SCMPAuthHashTreeExtn)(nil)

type SCMPAuthHashTreeExtn struct {
	*pkt_sec_extn.SCIONPacketSecurityBaseExtn
	height    uint8
	order     common.RawBytes
	signature common.RawBytes
	hashes    common.RawBytes
}

const (
	HEIGHT_LENGTH    = 1
	ORDER_LENGTH     = 3
	SIGNATURE_LENGTH = 64
	HASH_LENGTH      = 16

	HEIGHT_OFFSET    = pkt_sec_extn.SECMODE_LENGTH
	ORDER_OFFSET     = HEIGHT_OFFSET + HEIGHT_LENGTH
	SIGNATURE_OFFSET = ORDER_OFFSET + ORDER_LENGTH
	HASHES_OFFSET    = SIGNATURE_OFFSET + SIGNATURE_LENGTH
)

func NewSCMPAuthHashTreeExtn(treeHeight uint8) *SCMPAuthHashTreeExtn {
	s := &SCMPAuthHashTreeExtn{
		SCIONPacketSecurityBaseExtn: &pkt_sec_extn.SCIONPacketSecurityBaseExtn{
			SecMode: pkt_sec_extn.SCMP_AUTH_HASH_TREE}}

	s.height = treeHeight
	s.order = make(common.RawBytes, ORDER_LENGTH)
	s.signature = make(common.RawBytes, SIGNATURE_LENGTH)
	s.hashes = make(common.RawBytes, int(treeHeight)*HASH_LENGTH)
	return s
}

func (s SCMPAuthHashTreeExtn) UpdateHeight(height uint8) *common.Error {
	s.height = height
	return nil
}

func (s SCMPAuthHashTreeExtn) Height() uint8 {
	return s.height
}

func (s SCMPAuthHashTreeExtn) UpdateOrder(order common.RawBytes) *common.Error {
	if len(order) != ORDER_LENGTH {
		return common.NewError("Invalid order length", "len", len(order))
	}
	copy(s.order, order)
	return nil

}

func (s SCMPAuthHashTreeExtn) Order() common.RawBytes {
	return s.order
}

func (s SCMPAuthHashTreeExtn) UpdateSignature(signature common.RawBytes) *common.Error {
	if len(signature) != SIGNATURE_LENGTH {
		return common.NewError("Invalid signature length", "len", len(signature))
	}
	copy(s.signature, signature)
	return nil

}

func (s SCMPAuthHashTreeExtn) Signature() common.RawBytes {
	return s.signature
}

func (s SCMPAuthHashTreeExtn) UpdateHashes(hashes common.RawBytes) *common.Error {
	if len(hashes) != len(s.hashes) {
		return common.NewError("Invalid length", "len", len(hashes), "epected", len(s.hashes))
	}
	copy(s.hashes, hashes)
	return nil

}

func (s SCMPAuthHashTreeExtn) Hashes() common.RawBytes {
	return s.hashes
}

func (s *SCMPAuthHashTreeExtn) Write(b common.RawBytes) *common.Error {
	if len(b) < s.Len() {
		return common.NewError("Buffer too short", "method", "SCMPAuthHashTreeExtn.Write")
	}
	b[0] = s.SecMode
	b[HEIGHT_OFFSET] = s.height
	copy(b[ORDER_OFFSET:SIGNATURE_OFFSET], s.order)
	copy(b[SIGNATURE_OFFSET:HASHES_OFFSET], s.signature)
	copy(b[HASHES_OFFSET:], s.hashes)
	return nil
}

func (s *SCMPAuthHashTreeExtn) Pack() (common.RawBytes, *common.Error) {
	b := make(common.RawBytes, s.Len())
	if err := s.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *SCMPAuthHashTreeExtn) Copy() common.Extension {
	c := NewSCMPAuthHashTreeExtn(s.height)
	copy(c.order, s.order)
	copy(c.signature, s.signature)
	copy(c.hashes, s.hashes)
	return c
}

func (s *SCMPAuthHashTreeExtn) Len() int {
	return HASHES_OFFSET + len(s.hashes)
}

func (s *SCMPAuthHashTreeExtn) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "SCMPAuthHashTreeExtn (%dB): SecMode: %d\n", s.Len(), s.SecMode)
	fmt.Fprintf(buf, " Height: %x", s.height)
	fmt.Fprintf(buf, " Order: %s", s.order.String())
	fmt.Fprintf(buf, " Signature: %s", s.signature.String())
	fmt.Fprintf(buf, " Hashes: %s", s.hashes.String())
	return buf.String()
}
