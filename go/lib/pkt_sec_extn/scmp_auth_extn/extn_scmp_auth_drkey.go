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

package scmp

import (
	"bytes"
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/pkt_sec_extn"
)

var _ common.Extension = (*AuthDRKeyExtn)(nil)

type AuthDRKeyExtn struct {
	*spse.BaseExtn
	Direction uint8
	MAC       common.RawBytes
}

const (
	DirectionLength = 1
	PaddingLength   = 3
	MACLength       = 16

	DirectionOffset  = spse.SecModeLength
	MACOffset        = DirectionOffset + DirectionLength + PaddingLength
	DRKeyTotalLength = MACOffset + MACLength
)

const (
	AsToAs             uint8 = iota // Signed with S -> D
	AsToHost                        // Signed with S -> D:HD
	HostToHost                      // Signed with S:HS -> D:HD
	HostToAs                        // Signed with D -> S:HS
	AsToAsReversed                  // Signed with D -> S
	HostToHostReversed              // Signed with D:HD -> S:HS
)

func NewAuthDRKeyExtn() *AuthDRKeyExtn {
	s := &AuthDRKeyExtn{
		BaseExtn: &spse.BaseExtn{
			SecMode: spse.ScmpAuthDRKey}}
	s.MAC = make(common.RawBytes, MACLength)
	return s
}

func (s AuthDRKeyExtn) SetDirection(dir uint8) *common.Error {
	if dir < 0 || dir >= HostToHostReversed {
		return common.NewError("Invalid direction", "dir", dir)
	}
	s.Direction = dir
	return nil
}

func (s AuthDRKeyExtn) SetMAC(mac common.RawBytes) *common.Error {
	if len(mac) != MACLength {
		return common.NewError("Invalid MAC size", "len", mac)
	}
	copy(s.MAC, mac)
	return nil
}

func (s *AuthDRKeyExtn) Write(b common.RawBytes) *common.Error {
	if len(b) < s.Len() {
		return common.NewError("Buffer too short", "method", "SCMPAuthDRKeyExtn.Write")
	}
	b[0] = s.SecMode
	b[DirectionOffset] = s.Direction
	for i := DirectionOffset + DirectionLength; i < MACOffset; i++ {
		b[i] = 0
	}
	copy(b[MACOffset:DRKeyTotalLength], s.MAC)
	return nil
}

func (s *AuthDRKeyExtn) Pack() (common.RawBytes, *common.Error) {
	b := make(common.RawBytes, s.Len())
	if err := s.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *AuthDRKeyExtn) Copy() common.Extension {
	c := NewAuthDRKeyExtn()
	c.Direction = s.Direction
	copy(c.MAC, s.MAC)
	return c
}

func (s *AuthDRKeyExtn) Len() int {
	return DRKeyTotalLength
}

func (s *AuthDRKeyExtn) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "AuthDRKeyExtn (%dB): SecMode: %d\n", s.Len(), s.SecMode)
	fmt.Fprintf(buf, " Direction: %x", s.Direction)
	fmt.Fprintf(buf, " MAC: %s", s.MAC.String())
	return buf.String()
}
