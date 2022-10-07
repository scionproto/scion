// Copyright 2020 Anapaya Systems
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

// +gobra

package path

import (
	"encoding/binary"
	"fmt"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
)

// InfoLen is the size of an InfoField in bytes.
const InfoLen = 8

// InfoField is the InfoField used in the SCION and OneHop path types.
//
// InfoField has the following format:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|r r r r r r P C|      RSV      |             SegID             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           Timestamp                           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type InfoField struct {
	// Peer is the peering flag. If set to true, then the forwarding path is built as a peering
	// path, which requires special processing on the dataplane.
	Peer bool
	// ConsDir is the construction direction flag. If set to true then the hop fields are arranged
	// in the direction they have been constructed during beaconing.
	ConsDir bool
	// SegID is a updatable field that is required for the MAC-chaining mechanism.
	SegID uint16
	// Timestamp created by the initiator of the corresponding beacon. The timestamp is expressed in
	// Unix time, and is encoded as an unsigned integer within 4 bytes with 1-second time
	// granularity.  This timestamp enables validation of the hop field by verification of the
	// expiration time and MAC.
	Timestamp uint32
}

// DecodeFromBytes populates the fields from a raw buffer.
// The buffer must be of length >= path.InfoLen.
//@ requires  len(raw) >= InfoLen
// DecodeFromBytes modifies *inf and reads (but does not modify) the contents of raw.
//@ preserves acc(inf) && acc(raw, 1/2)
// When a call that satisfies the precondition (len(raw) >= InfoLen) is made,
// the return value is guaranteed to be nil.
//@ ensures   err == nil
// DecodeFromBytes always terminates.
//@ decreases
func (inf *InfoField) DecodeFromBytes(raw []byte) (err error) {
	if len(raw) < InfoLen {
		return serrors.New("InfoField raw too short", "expected", InfoLen, "actual", len(raw))
	}
	inf.ConsDir = raw[0]&0x1 == 0x1
	inf.Peer = raw[0]&0x2 == 0x2
	//@ assert &raw[2:4][0] == &raw[2] && &raw[2:4][1] == &raw[3]
	inf.SegID = binary.BigEndian.Uint16(raw[2:4])
	//@ assert &raw[4:8][0] == &raw[4] && &raw[4:8][1] == &raw[5]
	//@ assert &raw[4:8][2] == &raw[6] && &raw[4:8][3] == &raw[7]
	inf.Timestamp = binary.BigEndian.Uint32(raw[4:8])
	return nil
}

// SerializeTo writes the fields into the provided buffer.
// The buffer must be of length >= path.InfoLen.
//@ requires  len(b) >= InfoLen
// SerializeTo modifies the contents of b and reads (but does not modify) the fields of inf.
//@ preserves acc(b) && acc(inf, 1/2)
// When a call that satisfies the precondition (len(b) >= InfoLen) is made,
// the return value is guaranteed to be nil.
//@ ensures   err == nil
// SerializeTo always terminates.
//@ decreases
func (inf *InfoField) SerializeTo(b []byte) (err error) {
	if len(b) < InfoLen {
		return serrors.New("buffer for InfoField too short", "expected", InfoLen,
			"actual", len(b))
	}
	b[0] = 0
	if inf.ConsDir {
		b[0] |= 0x1
	}
	if inf.Peer {
		b[0] |= 0x2
	}
	b[1] = 0 // reserved
	//@ assert &b[2:4][0] == &b[2] && &b[2:4][1] == &b[3]
	binary.BigEndian.PutUint16(b[2:4], inf.SegID)
	//@ assert &b[4:8][0] == &b[4] && &b[4:8][1] == &b[5]
	//@ assert &b[4:8][2] == &b[6] && &b[4:8][3] == &b[7]
	binary.BigEndian.PutUint32(b[4:8], inf.Timestamp)

	return nil
}

// UpdateSegID updates the SegID field by XORing the SegID field with the 2
// first bytes of the MAC. It is the beta calculation according to
// https://docs.scion.org/en/latest/protocols/scion-header.html#hop-field-mac-computation
//
//	UpdateSegID only accesses and modifies the contents of inf.SegID.
//
//@ preserves acc(&inf.SegID)
// UpdateSegID always terminates.
//@ decreases
func (inf *InfoField) UpdateSegID(hfMac [MacLen]byte) {
	//@ share hfMac
	inf.SegID = inf.SegID ^ binary.BigEndian.Uint16(hfMac[:2])
}

// String is not verified because Gobra does not yet support the fmt package.
//@ trusted
// String always terminates.
//@ decreases
func (inf InfoField) String() string {
	return fmt.Sprintf("{Peer: %t, ConsDir: %t, SegID: %d, Timestamp: %s}",
		inf.Peer, inf.ConsDir, inf.SegID, util.SecsToCompact(inf.Timestamp))
}
