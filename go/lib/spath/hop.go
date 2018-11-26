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
	"fmt"
	"hash"
	"io"
	"math"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

const (
	HopFieldLength    = common.LineLen
	DefaultHopFExpiry = ExpTimeType(63)
	MacLen            = 3
	ErrorHopFTooShort = "HopF too short"
	ErrorHopFBadMac   = "Bad HopF MAC"
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
		return nil, common.NewBasicError(ErrorHopFTooShort, nil,
			"min", HopFieldLength, "actual", len(b))
	}
	h := &HopField{}
	flags := b[0]
	h.Xover = flags&XoverMask != 0
	h.VerifyOnly = flags&VerifyOnlyMask != 0
	h.ExpTime = ExpTimeType(b[1])
	// Interface IDs are 12b each, encoded into 3B
	ifids := common.Order.Uint32(b[1:5])
	h.ConsIngress = common.IFIDType((ifids >> 12) & 0xFFF)
	h.ConsEgress = common.IFIDType(ifids & 0xFFF)
	h.Mac = make([]byte, MacLen)
	copy(h.Mac, b[5:HopFieldLength])
	return h, nil
}

func (h *HopField) Write(b common.RawBytes) {
	var flags uint8
	if h.Xover {
		flags |= XoverMask
	}
	if h.VerifyOnly {
		flags |= VerifyOnlyMask
	}
	b[0] = flags
	common.Order.PutUint32(b[1:5], h.expTimeIfIdsPack())
	copy(b[5:], h.Mac)
}

func (h *HopField) String() string {
	return fmt.Sprintf(
		"ConsIngress: %v ConsEgress: %v ExpTime: %v Xover: %v VerifyOnly: %v Mac: %v",
		h.ConsIngress, h.ConsEgress, h.ExpTime, h.Xover, h.VerifyOnly, h.Mac)
}

func (h *HopField) Verify(macH hash.Hash, tsInt uint32, prev common.RawBytes) error {
	if mac, err := h.CalcMac(macH, tsInt, prev); err != nil {
		return err
	} else if !bytes.Equal(h.Mac, mac) {
		return common.NewBasicError(ErrorHopFBadMac, nil, "expected", mac, "actual", h.Mac)
	}
	return nil
}

// CalcMac calculates the MAC of a HopField and its preceding HopField, if any.
// prev does not contain flags byte.
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
func (h *HopField) CalcMac(mac hash.Hash, tsInt uint32,
	prev common.RawBytes) (common.RawBytes, error) {

	all := make(common.RawBytes, macInputLen)
	common.Order.PutUint32(all, tsInt)
	all[4] = 0 // Ignore flags
	common.Order.PutUint32(all[5:], h.expTimeIfIdsPack())
	copy(all[9:], prev)
	tag, err := scrypto.Mac(mac, all)
	return tag[:MacLen], err
}

// WriteTo implements the io.WriterTo interface.
func (h *HopField) WriteTo(w io.Writer) (int64, error) {
	b := make(common.RawBytes, HopFieldLength)
	h.Write(b)
	n, err := w.Write(b)
	return int64(n), err
}

func (h *HopField) expTimeIfIdsPack() uint32 {
	// Interface IDs are 12 bits each, encoded into 3 Bytes.
	return uint32(h.ExpTime)<<24 | uint32(h.ConsIngress&0xFFF)<<12 | uint32(h.ConsEgress&0xFFF)
}

func (h *HopField) Eq(o *HopField) bool {
	return h.Xover == o.Xover && h.VerifyOnly == o.VerifyOnly && h.ExpTime == o.ExpTime &&
		h.ConsIngress == o.ConsIngress && h.ConsEgress == o.ConsEgress && bytes.Equal(h.Mac, o.Mac)
}

type ExpTimeType uint8

// ToDuration calculates the relative expiration time in seconds.
// Note that for a 0 value ExpTime, the minimal duration is ExpTimeUnit.
func (e ExpTimeType) ToDuration() time.Duration {
	return (time.Duration(e) + 1) * time.Duration(ExpTimeUnit) * time.Second
}
