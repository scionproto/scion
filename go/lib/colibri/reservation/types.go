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
	"encoding/binary"
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
)

// SegmentID identifies a COLIBRI segment reservation. The suffix differentiates
// reservations for the same AS.
type SegmentID struct {
	ASID   addr.AS
	Suffix [4]byte
}

var _ io.Reader = (*SegmentID)(nil)

const SegmentIDLen = 10

// NewSegmentID returns a new SegmentID
func NewSegmentID(AS addr.AS, suffix []byte) (*SegmentID, error) {
	if len(suffix) != 4 {
		return nil, serrors.New("wrong suffix length, should be 4", "actual_len", len(suffix))
	}
	id := SegmentID{ASID: AS}
	copy(id.Suffix[:], suffix)
	return &id, nil
}

// SegmentIDFromRawBuffers constructs a SegmentID from two separate buffers.
func SegmentIDFromRawBuffers(ASID, suffix []byte) (*SegmentID, error) {
	if len(ASID) < 6 || len(suffix) < 4 {
		return nil, serrors.New("buffers too small", "length_ASID", len(ASID),
			"length_suffix", len(suffix))
	}
	return NewSegmentID(addr.AS(binary.BigEndian.Uint64(append([]byte{0, 0}, ASID[:6]...))),
		suffix[:4])
}

// SegmentIDFromRaw constructs a SegmentID parsing a raw buffer.
func SegmentIDFromRaw(raw []byte) (
	*SegmentID, error) {

	if len(raw) < SegmentIDLen {
		return nil, serrors.New("buffer too small", "actual", len(raw),
			"min", SegmentIDLen)
	}
	return SegmentIDFromRawBuffers(raw[:6], raw[6:])
}

// Read serializes this SegmentID into the buffer.
func (id *SegmentID) Read(raw []byte) (int, error) {
	if len(raw) < SegmentIDLen {
		return 0, serrors.New("buffer too small", "actual", len(raw), "min", SegmentIDLen)
	}
	auxBuff := make([]byte, 8)
	binary.BigEndian.PutUint64(auxBuff, uint64(id.ASID))
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

// NewE2EID returns a new E2EID
func NewE2EID(AS addr.AS, suffix []byte) (*E2EID, error) {
	if len(suffix) != 10 {
		return nil, serrors.New("wrong suffix length, should be 10", "actual_len", len(suffix))
	}
	id := E2EID{ASID: AS}
	copy(id.Suffix[:], suffix)
	return &id, nil
}

// E2EIDFromRawBuffers constructs a E2DID from two separate buffers.
func E2EIDFromRawBuffers(ASID, suffix []byte) (*E2EID, error) {
	if len(ASID) < 6 || len(suffix) < 10 {
		return nil, serrors.New("buffers too small", "length_ASID", len(ASID),
			"length_suffix", len(suffix))
	}
	return NewE2EID(addr.AS(binary.BigEndian.Uint64(append([]byte{0, 0}, ASID[:6]...))),
		suffix[:10])
}

// E2EIDFromRaw constructs an E2EID parsing a buffer.
func E2EIDFromRaw(raw []byte) (*E2EID, error) {
	if len(raw) < E2EIDLen {
		return nil, serrors.New("buffer too small", "actual", len(raw), "min", E2EIDLen)
	}
	return E2EIDFromRawBuffers(raw[:6], raw[6:])
}

func (id *E2EID) Read(raw []byte) (int, error) {
	if len(raw) < E2EIDLen {
		return 0, serrors.New("buffer too small", "actual", len(raw), "min", E2EIDLen)
	}
	auxBuff := make([]byte, 8)
	binary.BigEndian.PutUint64(auxBuff, uint64(id.ASID))
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

func (t Tick) ToTime() time.Time {
	return util.SecsToTime(uint32(t) * 4)
}

// BWCls is the bandwidth class. bandwidth = 16 * sqrt(2^(BWCls - 1)). 0 <= bwcls <= 63 .
type BWCls uint8

// Validate will return an error for invalid values.
func (b BWCls) Validate() error {
	if b > 63 {
		return serrors.New("invalid BWClass value", "bw_cls", b)
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
		return serrors.New("invalid BWClass", "bw_cls", c)
	}
	return nil
}

// IndexNumber is a 4 bit index for a reservation.
type IndexNumber uint8

// Validate will return an error for invalid values.
func (i IndexNumber) Validate() error {
	if i >= 1<<4 {
		return serrors.New("invalid IndexNumber", "value", i)
	}
	return nil
}

func (i IndexNumber) Add(other IndexNumber) IndexNumber {
	return (i + other) % 16
}

func (i IndexNumber) Sub(other IndexNumber) IndexNumber {
	return (i - other) % 16
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
		return serrors.New("invalid path type", "path_type", pt)
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
	Idx            IndexNumber
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
		return nil, serrors.New("buffer too small", "min_size", InfoFieldLen,
			"current_size", len(raw))
	}
	info := InfoField{
		ExpirationTick: Tick(binary.BigEndian.Uint32(raw[:4])),
		BWCls:          BWCls(raw[4]),
		RLC:            RLC(raw[5]),
		Idx:            IndexNumber(raw[6]) >> 4,
		PathType:       PathType(raw[6]) & 0x7,
	}
	if err := info.Validate(); err != nil {
		return nil, err
	}
	return &info, nil
}

// Read serializes this InfoField into a sequence of InfoFieldLen bytes.
func (f *InfoField) Read(b []byte) (int, error) {
	if len(b) < InfoFieldLen {
		return 0, serrors.New("buffer too small", "min_size", InfoFieldLen,
			"current_size", len(b))
	}
	binary.BigEndian.PutUint32(b[:4], uint32(f.ExpirationTick))
	b[4] = byte(f.BWCls)
	b[5] = byte(f.RLC)
	b[6] = byte(f.Idx<<4) | uint8(f.PathType)
	b[7] = 0 // b[7] is padding
	return 8, nil
}

// PathEndProps represent the zero or more properties a COLIBRI path can have at both ends.
type PathEndProps uint8

// The only current properties are "Local" (can be used to create e2e rsvs) and "Transfer" (can be
// stiched together with another segment reservation). The first 4 bits encode the properties
// of the "Start" AS, and the last 4 bits encode those of the "End" AS.
const (
	StartLocal    PathEndProps = 0x10
	StartTransfer PathEndProps = 0x20
	EndLocal      PathEndProps = 0x01
	EndTransfer   PathEndProps = 0x02
)

// Validate will return an error for invalid values.
func (pep PathEndProps) Validate() error {
	if pep&0x0F > 0x03 {
		return serrors.New("invalid path end properties (@End)", "path_end_props", pep)
	}
	if pep>>4 > 0x03 {
		return serrors.New("invalid path end properties (@Start)", "path_end_props", pep)
	}
	return nil
}

func NewPathEndProps(startLocal, startTransfer, endLocal, endTransfer bool) PathEndProps {
	var props PathEndProps
	if startLocal {
		props |= StartLocal
	}
	if startTransfer {
		props |= StartTransfer
	}
	if endLocal {
		props |= EndLocal
	}
	if endTransfer {
		props |= EndTransfer
	}
	return props
}

// AllocationBead represents an allocation resolved in an AS for a given reservation.
// It is used in an array to represent the allocation trail that happened for a reservation.
type AllocationBead struct {
	AllocBW uint8
	MaxBW   uint8
}

// Token is used in the data plane to forward COLIBRI packets.
type Token struct {
	InfoField
	HopFields []spath.HopField
}

// Validate will return an error for invalid values. It will not check the hop fields' validity.
func (t *Token) Validate() error {
	if len(t.HopFields) == 0 {
		return serrors.New("token without hop fields")
	}
	return t.InfoField.Validate()
}

// TokenFromRaw builds a Token from the passed bytes buffer.
func TokenFromRaw(raw []byte) (*Token, error) {
	if raw == nil {
		return nil, nil
	}
	rawHFs := len(raw) - InfoFieldLen
	if rawHFs < 0 || rawHFs%spath.HopFieldLength != 0 {
		return nil, serrors.New("buffer too small", "min_size", InfoFieldLen,
			"current_size", len(raw))
	}
	numHFs := rawHFs / spath.HopFieldLength
	inf, err := InfoFieldFromRaw(raw[:InfoFieldLen])
	if err != nil {
		return nil, err
	}
	t := Token{
		InfoField: *inf,
	}
	if numHFs > 0 {
		t.HopFields = make([]spath.HopField, numHFs)
	}
	for i := 0; i < numHFs; i++ {
		offset := InfoFieldLen + i*spath.HopFieldLength
		hf, err := spath.HopFFromRaw(raw[offset : offset+spath.HopFieldLength])
		if err != nil {
			return nil, err
		}
		t.HopFields[i] = *hf
	}
	return &t, nil
}

// Len returns the number of bytes of this token if serialized.
func (t *Token) Len() int {
	if t == nil {
		return 0
	}
	return InfoFieldLen + len(t.HopFields)*spath.HopFieldLength
}

// Read serializes this Token to the passed buffer.
func (t *Token) Read(b []byte) (int, error) {
	length := t.Len()
	if len(b) < length {
		return 0, serrors.New("buffer too small", "min_size", length, "current_size", len(b))
	}
	offset, err := t.InfoField.Read(b[:InfoFieldLen])
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(t.HopFields); i++ {
		t.HopFields[i].Write(b[offset : offset+spath.HopFieldLength])
		offset += spath.HopFieldLength
	}
	return offset, nil
}

// ToRaw returns the serial representation of the Token.
func (t *Token) ToRaw() []byte {
	buff := make([]byte, t.Len())
	if t != nil {
		t.Read(buff) // safely ignore errors as they can only come from buffer size
	}
	return buff
}
