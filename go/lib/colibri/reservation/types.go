// Copyright 2019 ETH Zurich, Anapaya Systems
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

package reservation

import (
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

// SegmentID identifies a COLIBRI segment reservation. The suffix differentiates
// reservations for the same AS.
type SegmentID struct {
	ASID   addr.AS
	Suffix [4]byte
}

const SegmentIDLen = 10

// SegmentIDFromRaw constructs a SegmentID parsing a raw buffer.
func SegmentIDFromRaw(raw []byte) (
	*SegmentID, error) {

	if len(raw) < SegmentIDLen {
		return nil, serrors.New("Buffer too small", "actual", len(raw),
			"min", SegmentIDLen)
	}
	id := SegmentID{
		ASID: addr.AS(common.Order.Uint64(append([]byte{0, 0}, raw[0:6]...))),
	}
	copy(id.Suffix[:], raw[6:10])
	return &id, nil
}

func (id *SegmentID) Read(raw []byte) (int, error) {
	if len(raw) < SegmentIDLen {
		return 0, serrors.New("Buffer too small", "actual", len(raw), "min", SegmentIDLen)
	}
	auxBuff := make([]byte, 8)
	common.Order.PutUint64(auxBuff, uint64(id.ASID))
	copy(raw, auxBuff[2:8])
	copy(raw[6:], id.Suffix[:])
	return SegmentIDLen, nil
}

// E2EID identifies a COLIBRI E2E reservation. The suffix is different for each
// reservation for any given AS.
type E2EID struct {
	ASID   addr.AS
	Suffix [10]byte
}

const E2EIDLen = 16

// E2EIDFromRaw constructs an E2EID parsing a buffer.
func E2EIDFromRaw(raw []byte) (*E2EID, error) {
	if len(raw) < E2EIDLen {
		return nil, serrors.New("Buffer too small", "actual", len(raw), "min", E2EIDLen)
	}
	id := E2EID{
		ASID: addr.AS(common.Order.Uint64(append([]byte{0, 0}, raw[0:6]...))),
	}
	copy(id.Suffix[:], raw[6:16])
	return &id, nil
}

func (id *E2EID) Read(raw []byte) (int, error) {
	if len(raw) < E2EIDLen {
		return 0, serrors.New("Buffer too small", "actual", len(raw), "min", E2EIDLen)
	}
	auxBuff := make([]byte, 8)
	common.Order.PutUint64(auxBuff, uint64(id.ASID))
	copy(raw, auxBuff[2:8])
	copy(raw[6:], id.Suffix[:])
	return E2EIDLen, nil
}

// Tick represents a slice of time of 4 seconds.
type Tick uint32

// TickFromTime returns the tick for a given time.
func TickFromTime(t time.Time) Tick {
	return Tick(util.TimeToSecs(t) / 4)
}

// BWCls is the bandwidth class. bandwidth = 16 * sqrt(2^(BWCls - 1)). 0 <= bwcls <= 63 .
type BWCls uint8

// Validate will return an error for invalid values.
func (b BWCls) Validate() error {
	if b > 63 {
		return serrors.New("Invalid BWClass value", "BWCls", b)
	}
	return nil
}

// SplitCls is the traffic split parameter. split = sqrt(2^c). The split divides the bandwidth
// in control traffic (BW * split) and end to end traffic (BW * (1-s)). 0 <= splitCls <= 256 .
type SplitCls uint8

// RLC Request Latency Class. latency = 2^rlc miliseconds. 0 <= rlc <= 63
type RLC uint8

// Validate will return an error for invalid values.
func (c RLC) Validate() error {
	if c > 63 {
		return serrors.New("Invalid BWClass", "BWCls", c)
	}
	return nil
}

// Index is a 4 bit index for a reservation.
type Index uint8

// Validate will return an error for invalid values.
func (i Index) Validate() error {
	if i >= 1<<4 {
		return serrors.New("Invalid Index", "Index", i)
	}
	return nil
}

// PathType specifies which type of COLIBRI path this segment reservation or request refers to.
type PathType uint8

// the different COLIBRI path types.
const (
	UnknownPath PathType = iota
	DownPath
	UpPath
	PeeringDownPath
	PeeringUpPath
	E2EPath
	CorePath
)

// Validate will return an error for invalid values.
func (pt PathType) Validate() error {
	if pt == UnknownPath || pt > CorePath {
		return serrors.New("Invalid path type", "PathType", pt)
	}
	return nil
}

// InfoField is used in the reservation token and segment request data.
// 0B       1        2        3        4        5        6        7
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | Expiration time (4B)              |  BwCls | RTT Cls|Idx|Type| padding|
// +--------+--------+--------+--------+--------+--------+--------+--------+
//
// The bandwidth class (BwCls) indicates the reserved bandwidth in an active
// reservation. In a steady request, it indicates the minimal bandwidth class
// reserved so far. In a ephemeral request, it indicates the bandwidth class
// that the source end host is seeking to reserve.
//
// The round trip class (RTT Cls) allows for more granular control in the
// pending request garbage collection.
//
// The reservation index (Idx) is used to allow for multiple overlapping
// reservations within a single path, which enables renewal and changing the
// bandwidth requested.
//
// Type indicates which path type of the reservation.
type InfoField struct {
	ExpirationTick Tick
	BWCls          BWCls
	RLC            RLC
	Idx            Index
	PathType       PathType
}

// InfoFieldLen is the length in bytes of the InfoField.
const InfoFieldLen = 8

// Validate will return an error for invalid values.
func (f *InfoField) Validate() error {
	if err := f.BWCls.Validate(); err != nil {
		return err
	}
	if err := f.RLC.Validate(); err != nil {
		return err
	}
	if err := f.Idx.Validate(); err != nil {
		return err
	}
	if err := f.PathType.Validate(); err != nil {
		return err
	}

	return nil
}

// InfoFieldFromRaw builds an InfoField from the InfoFieldLen bytes buffer.
func InfoFieldFromRaw(raw []byte) (*InfoField, error) {
	if len(raw) < InfoFieldLen {
		return nil, serrors.New("Buffer too small", "min size", InfoFieldLen,
			"current size", len(raw))
	}
	info := InfoField{
		ExpirationTick: Tick(common.Order.Uint32(raw[:4])),
		BWCls:          BWCls(raw[4]),
		RLC:            RLC(raw[5]),
		Idx:            Index(raw[6]) >> 4,
		PathType:       PathType(raw[6]) & 0x7,
	}
	if err := info.Validate(); err != nil {
		return nil, err
	}
	return &info, nil
}

// Read serializes this InfoField into an array of InfoFieldLen bytes.
func (f *InfoField) Read(b []byte) (int, error) {
	if len(b) < InfoFieldLen {
		return 0, serrors.New("Buffer too short", "size", len(b))
	}
	common.Order.PutUint32(b[:4], uint32(f.ExpirationTick))
	b[4] = byte(f.BWCls)
	b[5] = byte(f.RLC)
	b[6] = byte(f.Idx<<4) | uint8(f.PathType)
	b[7] = 0 // b[7] is padding
	return 8, nil
}
