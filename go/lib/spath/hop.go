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

type ExpTimeType uint8

func (e ExpTimeType) ToDuration() time.Duration {
	return time.Duration(e+1) * time.Duration(ExpTimeUnit) * time.Second
}

type HopField struct {
	data       common.RawBytes
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
	Mac    common.RawBytes
	length int
}

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

func NewHopField(b common.RawBytes, in common.IFIDType,
	out common.IFIDType, expTime ExpTimeType) *HopField {

	h := &HopField{}
	h.data = b
	h.ExpTime = expTime
	h.ConsIngress = in
	h.ConsEgress = out
	h.Write()
	return h
}

// HopFFromRaw returns a HopField object from the raw content in b.
//
// The new HopField object takes ownership of the first HopFieldLength bytes in
// b. Changing fields in the new object and calling Write will mutate the
// initial bytes in b.
func HopFFromRaw(b []byte) (*HopField, error) {
	if len(b) < HopFieldLength {
		return nil, common.NewBasicError(ErrorHopFTooShort, nil,
			"min", HopFieldLength, "actual", len(b))
	}
	h := &HopField{}
	h.data = b[:HopFieldLength]
	flags := h.data[0]
	h.Xover = flags&XoverMask != 0
	h.VerifyOnly = flags&VerifyOnlyMask != 0
	h.Recurse = flags&RecurseMask != 0
	offset := 1
	h.ExpTime = ExpTimeType(h.data[offset])
	offset += 1
	// Interface IDs are 12b each, encoded into 3B
	h.ConsIngress = common.IFIDType(int(h.data[offset])<<4 | int(h.data[offset+1])>>4)
	h.ConsEgress = common.IFIDType((int(h.data[offset+1])&0xF)<<8 | int(h.data[offset+2]))
	offset += 3
	h.Mac = h.data[offset:]
	h.length = common.LineLen
	return h, nil
}

// Len returns the length (in bytes)
func (h *HopField) Len() int {
	return h.length
}

func (h *HopField) Write() {
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
	h.data[0] = flags
	h.data[1] = uint8(h.ExpTime)
	// Interface IDs are 12b each, encoded into 3B
	h.data[2] = byte(h.ConsIngress >> 4)
	h.data[3] = byte((h.ConsIngress&0x0F)<<4 | h.ConsEgress>>8)
	h.data[4] = byte(h.ConsEgress & 0xFF)
	copy(h.data[5:], h.Mac)
}

func (h *HopField) String() string {
	return fmt.Sprintf("ConsIngress: %v ConsEgress: %v ExpTime: %v Xover: %v VerifyOnly: %v "+
		"Mac: %v",
		h.ConsIngress, h.ConsEgress, h.ExpTime, h.Xover, h.VerifyOnly, h.Mac)
}

func (h *HopField) Verify(mac hash.Hash, tsInt uint32, prev common.RawBytes) error {
	if mac, err := h.CalcMac(mac, tsInt, prev); err != nil {
		return err
	} else if !bytes.Equal(h.Mac, mac) {
		return common.NewBasicError(ErrorHopFBadMac, nil, "expected", h.Mac, "actual", mac)
	}
	return nil
}

// CalcMac calculates the MAC of a HopField and its preceeding HopField, if any.
func (h *HopField) CalcMac(mac hash.Hash, tsInt uint32,
	prev common.RawBytes) (common.RawBytes, error) {
	all := make(common.RawBytes, macInputLen)
	common.Order.PutUint32(all, tsInt)
	all[4] = 0 // Ignore flags
	copy(all[5:], h.data[1:5])
	copy(all[9:], prev)
	tag, err := scrypto.Mac(mac, all)
	return tag[:MacLen], err
}

// WriteTo implements the io.WriterTo interface.
func (h *HopField) WriteTo(w io.Writer) (int64, error) {
	h.Write()
	n, err := w.Write(h.data)
	return int64(n), err
}
