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

package scmp_auth

import (
	"bytes"
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spse"
)

var _ common.Extension = (*DRKeyExtn)(nil)

// DRKeyExtn is an implementation of the SCMPAuthDRKey extension.
// It is used to authenticate scmp messages.
type DRKeyExtn struct {
	*spse.BaseExtn
	// Direction indicates which key has been used during authentication.
	Direction Dir
	// MAC is the mac of the SCION Packet with CurrHF and CurrINF set to zero.
	MAC common.RawBytes
}

const (
	DirectionLength = 1
	PaddingLength   = 3
	MACLength       = 16

	DirectionOffset  = spse.SecModeLength
	MACOffset        = DirectionOffset + DirectionLength + PaddingLength
	DRKeyTotalLength = MACOffset + MACLength
)

type Dir uint8

const (
	AsToAs             Dir = iota // Authenticated with S -> D
	AsToHost                      // Authenticated with S -> D:HD
	HostToHost                    // Authenticated with S:HS -> D:HD
	HostToAs                      // Authenticated with D -> S:HS
	AsToAsReversed                // Authenticated with D -> S
	HostToHostReversed            // Authenticated with D:HD -> S:HS
)

func (d Dir) String() string {
	switch d {
	case AsToAs:
		return "AS to AS"
	case AsToHost:
		return "AS to Host"
	case HostToHost:
		return "Host to Host"
	case HostToAs:
		return "Host to AS"
	case AsToAsReversed:
		return "AS to AS reversed"
	case HostToHostReversed:
		return "Host to Host reversed"
	default:
		return fmt.Sprintf("UNKNOWN: %v", uint8(d))
	}
}

func NewDRKeyExtn() *DRKeyExtn {
	s := &DRKeyExtn{BaseExtn: &spse.BaseExtn{SecMode: spse.ScmpAuthDRKey}}
	s.MAC = make(common.RawBytes, MACLength)
	return s
}

func (s DRKeyExtn) SetDirection(dir Dir) error {
	if dir > HostToHostReversed {
		return common.NewBasicError("Invalid direction", nil, "dir", dir)
	}
	s.Direction = dir
	return nil
}

func (s DRKeyExtn) SetMAC(mac common.RawBytes) error {
	if len(mac) != MACLength {
		return common.NewBasicError("Invalid MAC size", nil,
			"expected", MACLength, "actual", len(mac))
	}
	copy(s.MAC, mac)
	return nil
}

func (s *DRKeyExtn) Write(b common.RawBytes) error {
	if len(b) < s.Len() {
		return common.NewBasicError("Buffer too short", nil,
			"method", "SCMPAuthDRKeyExtn.Write", "expected", s.Len(), "actual", len(b))
	}
	b[0] = uint8(s.SecMode)
	b[DirectionOffset] = uint8(s.Direction)
	for i := DirectionOffset + DirectionLength; i < MACOffset; i++ {
		b[i] = 0
	}
	copy(b[MACOffset:DRKeyTotalLength], s.MAC)
	return nil
}

func (s *DRKeyExtn) Pack() (common.RawBytes, error) {
	b := make(common.RawBytes, s.Len())
	if err := s.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *DRKeyExtn) Copy() common.Extension {
	c := NewDRKeyExtn()
	c.Direction = s.Direction
	copy(c.MAC, s.MAC)
	return c
}

func (s *DRKeyExtn) Len() int {
	return DRKeyTotalLength
}

func (s *DRKeyExtn) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "AuthDRKeyExtn (%dB): SecMode: %d\n", s.Len(), s.SecMode)
	fmt.Fprintf(buf, " Direction: %x", s.Direction)
	fmt.Fprintf(buf, " MAC: %s", s.MAC.String())
	return buf.String()
}
