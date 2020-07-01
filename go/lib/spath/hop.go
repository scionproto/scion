// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

package spath

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

var (
	ErrorHopFTooShort = serrors.New("HopF too short")
	ErrorHopFBadMac   = serrors.New("Bad HopF MAC")
)

const (
	HopFieldLength    = common.LineLen
	DefaultHopFExpiry = ExpTimeType(63)
	MacLen            = 3
	XoverMask         = 0x01
	VerifyOnlyMask    = 0x02
	MaxTTL            = 24 * 60 * 60 // One day in seconds
	ExpTimeUnit       = MaxTTL / 256 // ~5m38s
	MaxTTLField       = ExpTimeType(math.MaxUint8)
	macInputLen       = 16
)

// Hop Field format:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |r r r r r r V X|    ExpTime    |      ConsIngress      |  ...  |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  | ...ConsEgress |                      MAC                      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// The absolute expiration time in seconds of a Hop Field is calculated as:
//
// TS + ( (1 + ExpTime) * ExpTimeUnit ), where TS is the Info Field Timestamp.
//
type HopField struct {
	Xover      bool
	VerifyOnly bool
	// ExpTime defines for how long this HopField is valid, expressed as the number
	// of ExpTimeUnits relative to the PathSegments's InfoField.Timestamp().
	// A 0 value means the minimum expiration time of ExpTimeUnit.
	// See ToDuration() for how to convert from ExpTimeUnits to Seconds.
	ExpTime ExpTimeType
	// ConsIngress is the interface the PCB entered the AS during path construction.
	ConsIngress common.IFIDType
	// ConsEgress is the interface the PCB exited the AS during path construction.
	ConsEgress common.IFIDType
	// Mac is the message authentication code of this HF,
	// see CalcMac() to see how it should be calculated.
	Mac common.RawBytes
}

// HopFFromRaw returns a HopField object from the raw content in b.
func HopFFromRaw(b []byte) (*HopField, error) {
	if len(b) < HopFieldLength {
		return nil, serrors.WithCtx(ErrorHopFTooShort, "min", HopFieldLength, "actual", len(b))
	}
	h := &HopField{}
	flags := b[0]
	h.Xover = flags&XoverMask != 0
	h.VerifyOnly = flags&VerifyOnlyMask != 0
	h.ExpTime = ExpTimeType(b[1])
	// Interface IDs are 12b each, encoded into 3B
	ifids := binary.BigEndian.Uint32(b[1:5])
	h.ConsIngress = common.IFIDType((ifids >> 12) & 0xFFF)
	h.ConsEgress = common.IFIDType(ifids & 0xFFF)
	h.Mac = make([]byte, MacLen)
	copy(h.Mac, b[5:HopFieldLength])
	return h, nil
}

func (h *HopField) Write(b common.RawBytes) {
	_ = b[7]
	var flags uint8
	if h.Xover {
		flags |= XoverMask
	}
	if h.VerifyOnly {
		flags |= VerifyOnlyMask
	}
	b[0] = flags
	binary.BigEndian.PutUint32(b[1:5], h.expTimeIfIdsPack())
	copy(b[5:], h.Mac)
}

func (h *HopField) String() string {
	return fmt.Sprintf(
		"ConsIngress: %v ConsEgress: %v ExpTime: %v Xover: %v VerifyOnly: %v Mac: %v",
		h.ConsIngress, h.ConsEgress, h.ExpTime, h.Xover, h.VerifyOnly, h.Mac)
}

// Verify checks the MAC. The same restrictions on prev as in CalcMac apply, and
// the function may panic otherwise.
func (h *HopField) Verify(macH hash.Hash, tsInt uint32, prev common.RawBytes) error {
	mac := h.CalcMac(macH, tsInt, prev)
	if !bytes.Equal(h.Mac, mac) {
		return serrors.WithCtx(ErrorHopFBadMac, "expected", mac, "actual", h.Mac)
	}
	return nil
}

// CalcMac calculates the MAC of a HopField and its preceding HopField, if any.
// prev does not contain flags byte. This implies that the length of prev can
// either be 0 or k*8+7, where k >=0.
// WARN: If prev is of different length, this function panics.
//
// MAC input block format:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                           Timestamp                           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |       0       |    ExpTime    |      ConsIngress      |  ...  |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  | ...ConsEgress |                                               |
//  +-+-+-+-+-+-+-+-+                                               |
//  |                           PrevHopF                            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
func (h *HopField) CalcMac(mac hash.Hash, tsInt uint32, prev common.RawBytes) common.RawBytes {
	// If the previous hopfield is set, it must be of length k*8+7 (k >= 0),
	if len(prev) != 0 && (len(prev)&0x7) != 7 {
		panic(fmt.Sprintf("Bad previous hop field length len=%d", len(prev)))
	}
	all := make(common.RawBytes, macInputLen)
	binary.BigEndian.PutUint32(all, tsInt)
	all[4] = 0 // Ignore flags
	binary.BigEndian.PutUint32(all[5:], h.expTimeIfIdsPack())
	copy(all[9:], prev)

	mac.Reset()
	// Write must not return an error: https://godoc.org/hash#Hash
	if _, err := mac.Write(all); err != nil {
		panic(err)
	}
	tmp := make([]byte, 0, mac.Size())
	return mac.Sum(tmp)[:MacLen]
}

// Pack packs the hop field.
func (h *HopField) Pack() common.RawBytes {
	b := make(common.RawBytes, HopFieldLength)
	h.Write(b)
	return b
}

// WriteTo implements the io.WriterTo interface.
func (h *HopField) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(h.Pack())
	return int64(n), err
}

func (h *HopField) expTimeIfIdsPack() uint32 {
	// Interface IDs are 12 bits each, encoded into 3 Bytes.
	return uint32(h.ExpTime)<<24 | uint32(h.ConsIngress&0xFFF)<<12 | uint32(h.ConsEgress&0xFFF)
}

func (h *HopField) Equal(o *HopField) bool {
	if h == nil || o == nil {
		return h == o
	}
	return h.Xover == o.Xover && h.VerifyOnly == o.VerifyOnly && h.ExpTime == o.ExpTime &&
		h.ConsIngress == o.ConsIngress && h.ConsEgress == o.ConsEgress && bytes.Equal(h.Mac, o.Mac)
}

// ExpTimeType describes the relative expiration time of the hop field.
type ExpTimeType uint8

// ExpTimeFromDuration converts a time duration to the relative expiration
// time.
//
// Round Up Mode:
//
// The round up mode guarantees that the resulting relative expiration time
// is more than the provided duration. The duration is rounded up to the
// next unit, and then 1 is subtracted from the result, e.g. 1.3 is rounded
// to 1. In case the requested duration exceeds the maximum value for the
// expiration time (256*Unit) in this mode, an error is returned.
//
// Round Down Mode:
//
// The round down mode guarantees that the resulting relative expiration
// time is less than the provided duration. The duration is rounded down to
// the next unit, and then 1 is subtracted from the result, e.g. 1.3 is
// rounded to 0. In case the requested duration is below the unit for the
// expiration time in this mode, an error is returned.
func ExpTimeFromDuration(duration time.Duration, roundUp bool) (ExpTimeType, error) {
	unit := time.Duration(ExpTimeUnit) * time.Second
	if duration > (time.Duration(MaxTTLField)+1)*unit {
		if roundUp {
			return 0, common.NewBasicError("Requested duration exceeds maximum value", nil,
				"duration", duration, "max", MaxTTLField.ToDuration())
		}
		return MaxTTLField, nil
	}
	if duration < unit {
		if !roundUp {
			return 0, common.NewBasicError("Requested duration below minimum value", nil,
				"duration", duration, "min", ExpTimeType(0).ToDuration())
		}
		return 0, nil
	}
	if roundUp {
		return ExpTimeType((duration - 1) / unit), nil
	}
	return ExpTimeType((duration / unit) - 1), nil
}

// ToDuration calculates the relative expiration time in seconds.
// Note that for a 0 value ExpTime, the minimal duration is ExpTimeUnit.
func (e ExpTimeType) ToDuration() time.Duration {
	return (time.Duration(e) + 1) * time.Duration(ExpTimeUnit) * time.Second
}
