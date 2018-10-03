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
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// Hop Field format:
//
//  0b     7        15           27           39                         63
// +--------+--------+------------+------------+--------+--------+--------+
// | Flags  | ExpTime| ConsIngress| ConsEgress |           MAC            |
// +--------+--------+------------+------------+--------+--------+--------+
//
const (
	HopFieldLength    = common.LineLen
	DefaultHopFExpiry = ExpTimeType(63)
	MacLen            = 3
	ErrorHopFTooShort = "HopF too short"
	ErrorHopFBadMac   = "Bad HopF MAC"
	XoverMask         = 0x01
	VerifyOnlyMask    = 0x02
	RecurseMask       = 0x04
)

func (e ExpTimeType) ToDuration() time.Duration {
	return time.Duration(e+1) * time.Duration(ExpTimeUnit) * time.Second
}

type HopField struct {
	Xover      bool
	VerifyOnly bool
	Recurse    bool
	// ExpTime defines for how long this HopField is valid,
	// relative to the PathSegments's InfoField.Timestamp().
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
	h.Recurse = flags&RecurseMask != 0
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
	if h.Recurse {
		flags |= RecurseMask
	}
	b[0] = flags
	// Interface IDs are 12b each, encoded into 3B
	tmp := uint32(h.ExpTime)<<24 | uint32(h.ConsIngress&0xFFF)<<12 | uint32(h.ConsEgress&0xFFF)
	common.Order.PutUint32(b[1:5], tmp)
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
		return common.NewBasicError(ErrorHopFBadMac, nil, "expected", h.Mac, "actual", mac)
	}
	return nil
}

// CalcMac calculates the MAC of a HopField and its preceeding HopField, if any.
// prev does not contain flags byte.
func (h *HopField) CalcMac(mac hash.Hash, tsInt uint32,
	prev common.RawBytes) (common.RawBytes, error) {

	all := make(common.RawBytes, macInputLen)
	common.Order.PutUint32(all, tsInt)
	all[4] = 0 // Ignore flags
	tmp := uint32(h.ExpTime)<<24 | uint32(h.ConsIngress&0xFFF)<<12 | uint32(h.ConsEgress&0xFFF)
	common.Order.PutUint32(all[5:], tmp)
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

type ExpTimeType uint8
