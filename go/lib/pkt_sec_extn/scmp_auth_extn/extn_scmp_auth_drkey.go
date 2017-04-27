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

//    DRKeyMac:
//
//    0B       1        2        3        4        5        6        7
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x04  |  dir   |         padding          |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                              DRKey MAC                                |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                              DRKey MAC (continued)                    |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//

package scmp_auth_extn

import (
	"bytes"
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/pkt_sec_extn"
)

var _ common.Extension = (*SCMPAuthDRKeyExtn)(nil)

type SCMPAuthDRKeyExtn struct {
	*pkt_sec_extn.SCIONPacketSecurityBaseExtn
	direction uint8
	mac       common.RawBytes
}

const (
	DIRECTION_LENGTH = 1
	PADDING_LENTH    = 3
	MAC_LENGTH       = 16

	DIRECTION_OFFSET   = pkt_sec_extn.SECMODE_LENGTH
	MAC_OFFSET         = DIRECTION_OFFSET + DIRECTION_LENGTH + PADDING_LENTH
	DRKEY_TOTAL_LENGTH = MAC_OFFSET + MAC_LENGTH
)

const (
	AS_TO_AS              uint8 = iota // Signed with S -> D
	AS_TO_HOST                         // Signed with S -> D:HD
	HOST_TO_HOST                       // Signed with S:HS -> D:HD
	HOST_TO_AS                         // Signed with D -> S:HS
	AS_TO_AS_REVERSED                  // Signed with D -> S
	HOST_TO_HOST_REVERSED              // Signed with D:HD -> S:HS
)

func NewSCMPAuthDRKeyExtn() *SCMPAuthDRKeyExtn {
	s := &SCMPAuthDRKeyExtn{
		SCIONPacketSecurityBaseExtn: &pkt_sec_extn.SCIONPacketSecurityBaseExtn{
			SecMode: pkt_sec_extn.SCMP_AUTH_DRKEY}}
	s.mac = make(common.RawBytes, MAC_LENGTH)
	return s
}

func (s SCMPAuthDRKeyExtn) UpdateDirection(dir uint8) *common.Error {
	if dir < 0 || dir >= HOST_TO_HOST_REVERSED {
		return common.NewError("Invalid direction", "dir", dir)
	}
	s.direction = dir
	return nil
}

func (s SCMPAuthDRKeyExtn) Direction() uint8 {
	return s.direction
}

func (s SCMPAuthDRKeyExtn) UpdateMAC(mac common.RawBytes) *common.Error {
	if len(mac) != MAC_LENGTH {
		return common.NewError("Invalid MAC size", "len", mac)
	}
	copy(s.mac, mac)
	return nil
}

func (s SCMPAuthDRKeyExtn) MAC() common.RawBytes {
	return s.mac
}

func (s *SCMPAuthDRKeyExtn) Write(b common.RawBytes) *common.Error {
	if len(b) < s.Len() {
		return common.NewError("Buffer too short", "method", "SCMPAuthDRKeyExtn.Write")
	}
	b[0] = s.SecMode
	b[DIRECTION_OFFSET] = s.direction
	for i := DIRECTION_OFFSET + DIRECTION_LENGTH; i < MAC_OFFSET; i++ {
		b[i] = 0
	}
	copy(b[MAC_OFFSET:DRKEY_TOTAL_LENGTH], s.mac)
	return nil
}

func (s *SCMPAuthDRKeyExtn) Pack() (common.RawBytes, *common.Error) {
	b := make(common.RawBytes, s.Len())
	if err := s.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *SCMPAuthDRKeyExtn) Copy() common.Extension {
	c := NewSCMPAuthDRKeyExtn()
	c.direction = s.direction
	copy(c.mac, s.mac)
	return c
}

func (s *SCMPAuthDRKeyExtn) Len() int {
	return DRKEY_TOTAL_LENGTH
}

func (s *SCMPAuthDRKeyExtn) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "SCMPAuthDRKeyExtn (%dB): SecMode: %d\n", s.Len(), s.SecMode)
	fmt.Fprintf(buf, " Direction: %x", s.direction)
	fmt.Fprintf(buf, " MAC: %s", s.mac.String())
	return buf.String()
}
