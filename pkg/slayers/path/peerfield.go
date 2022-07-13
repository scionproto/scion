// Copyright 2022 Thorben Krüger
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

package path

import (
	"encoding/binary"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// PeerField is the HopField used in the SCION peer path type.
//
// The Peer Field has the following format:
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |r r r r r r I E|    ExpTime    |           PeerIF              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       EgressIF                |                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//   |                              MAC                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type PeerField struct {
	Flags uint8
	// Timestamp + (1 + ExpTime) * (24*60*60)/256
	ExpTime uint8
	// PeerIF is the interface ID of the remote peer
	PeerIF uint16
	// EgressIF is local egress interface ID.
	EgressIF uint16
	// Mac is the 6-byte Message Authentication Code to authenticate the PeerField.
	Mac [MacLen]byte
}

// DecodeFromBytes populates the fields from a raw buffer. The buffer must be of length >=
// path.HopLen.
func (p *PeerField) DecodeFromBytes(raw []byte) error {
	if len(raw) < HopLen {
		return serrors.New("PeerField raw too short", "expected", HopLen, "actual", len(raw))
	}
	p.Flags = raw[0]
	p.ExpTime = raw[1]
	p.PeerIF = binary.BigEndian.Uint16(raw[2:4])
	p.EgressIF = binary.BigEndian.Uint16(raw[4:6])
	copy(p.Mac[:], raw[6:6+MacLen])
	return nil
}

// SerializeTo writes the fields into the provided buffer. The buffer must be of length >=
// path.HopLen.
func (p *PeerField) SerializeTo(b []byte) error {
	if len(b) < HopLen {
		return serrors.New("buffer for PeerField too short", "expected", MacLen, "actual", len(b))
	}
	b[0] = p.Flags
	b[1] = p.ExpTime
	binary.BigEndian.PutUint16(b[2:4], p.PeerIF)
	binary.BigEndian.PutUint16(b[4:6], p.EgressIF)
	copy(b[6:6+MacLen], p.Mac[:])

	return nil
}
