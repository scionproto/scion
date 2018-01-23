// Copyright 2016 ETH Zurich
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

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type HopField struct {
	data        common.RawBytes
	Xover       bool
	VerifyOnly  bool
	ForwardOnly bool
	Recurse     bool
	ExpTime     uint8
	Ingress     common.IFIDType
	Egress      common.IFIDType
	Mac         common.RawBytes
	length      int
}

const (
	HopFieldVerifyFlags = 0x4 // Forward-only
	HopFieldLength      = common.LineLen
	DefaultHopFExpiry   = 63
	MacLen              = 3
	ErrorHopFTooShort   = "HopF too short"
	ErrorHopFBadMac     = "Bad HopF MAC"
)

func NewHopField(b common.RawBytes, in common.IFIDType, out common.IFIDType) *HopField {
	h := &HopField{}
	h.data = b
	h.ExpTime = DefaultHopFExpiry
	h.Ingress = in
	h.Egress = out
	h.Write()
	return h
}

func HopFFromRaw(b []byte) (*HopField, error) {
	if len(b) < HopFieldLength {
		return nil, common.NewCError(ErrorHopFTooShort, "min", HopFieldLength, "actual", len(b))
	}
	h := &HopField{}
	h.data = b[:HopFieldLength]
	flags := h.data[0]
	h.Xover = flags&0x1 != 0
	h.VerifyOnly = flags&0x2 != 0
	h.ForwardOnly = flags&0x4 != 0
	h.Recurse = flags&0x8 != 0
	offset := 1
	h.ExpTime = h.data[offset]
	offset += 1
	// Interface IDs are 12b each, encoded into 3B
	h.Ingress = common.IFIDType(int(h.data[offset])<<4 | int(h.data[offset+1])>>4)
	h.Egress = common.IFIDType((int(h.data[offset+1])&0xF)<<8 | int(h.data[offset+2]))
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
		flags |= 0x1
	}
	if h.VerifyOnly {
		flags |= 0x2
	}
	if h.ForwardOnly {
		flags |= 0x4
	}
	if h.Recurse {
		flags |= 0x8
	}
	h.data[0] = flags
	h.data[1] = h.ExpTime
	// Interface IDs are 12b each, encoded into 3B
	h.data[2] = byte(h.Ingress >> 4)
	h.data[3] = byte((h.Ingress&0x0F)<<4 | h.Egress>>4)
	h.data[4] = byte(h.Egress & 0xFF)
	copy(h.data[5:], h.Mac)
}

func (h *HopField) String() string {
	return fmt.Sprintf(
		"Ingress: %v Egress: %v ExpTime: %v Xover: %v VerifyOnly: %v ForwardOnly: %v Mac: %v",
		h.Ingress, h.Egress, h.ExpTime, h.Xover, h.VerifyOnly, h.ForwardOnly, h.Mac)
}

func (h *HopField) Verify(mac hash.Hash, tsInt uint32, prev common.RawBytes) error {
	if mac, err := h.CalcMac(mac, tsInt, prev); err != nil {
		return err
	} else if !bytes.Equal(h.Mac, mac) {
		return common.NewCError(ErrorHopFBadMac, "expected", h.Mac, "actual", mac)
	}
	return nil
}

// CalcMac calculates the MAC of a Hop Field and its preceeding Hop Field, if any.
func (h *HopField) CalcMac(mac hash.Hash, tsInt uint32,
	prev common.RawBytes) (common.RawBytes, error) {
	all := make(common.RawBytes, macInputLen)
	common.Order.PutUint32(all, tsInt)
	all[4] = h.data[0] & HopFieldVerifyFlags
	copy(all[5:], h.data[1:5])
	copy(all[9:], prev)
	tag, err := util.Mac(mac, all)
	return tag[:MacLen], err
}
