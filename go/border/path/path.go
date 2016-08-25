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

package path

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"time"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type IntfID uint16

type InfoField struct {
	Up       bool
	Shortcut bool
	Peer     bool
	TsInt    uint32
	ISD      uint16
	Hops     uint8
}

const (
	MaxTTL      = 24 * 60 * 60 // One day in seconds
	ExpTimeUnit = MaxTTL / 2 << 8
	macInputLen = 16
)

var order = binary.BigEndian

const (
	ErrorInfoFTooShort = "InfoF too short"
	ErrorHopFTooShort  = "HopF too short"
	ErrorHopFBadMac    = "Bad HopF mac"
)

func InfoFFromRaw(b []byte) (*InfoField, *util.Error) {
	if len(b) < spkt.LineLen {
		return nil, util.NewError(ErrorInfoFTooShort, "min", spkt.LineLen, "actual", len(b))
	}
	inf := &InfoField{}
	flags := b[0]
	inf.Up = flags&0x1 != 0
	inf.Shortcut = flags&0x2 != 0
	inf.Peer = flags&0x4 != 0
	offset := 1
	inf.TsInt = order.Uint32(b[offset:])
	offset += 4
	inf.ISD = order.Uint16(b[offset:])
	offset += 2
	inf.Hops = b[offset]
	return inf, nil
}

func (inf *InfoField) String() string {
	return fmt.Sprintf("ISD: %v TS: %v Hops: %v Up: %v Shortcut: %v Peer: %v",
		inf.ISD, inf.Timestamp(), inf.Hops, inf.Up, inf.Shortcut, inf.Peer)
}

func (inf *InfoField) Timestamp() time.Time {
	return time.Unix(int64(inf.TsInt), 0)
}

type HopField struct {
	data        util.RawBytes
	Xover       bool
	VerifyOnly  bool
	ForwardOnly bool
	Recurse     bool
	ExpTime     uint8
	Ingress     IntfID
	Egress      IntfID
	Mac         util.RawBytes
}

const (
	HopFieldVerifyFlags = 0x4 // Forward-only
	HopFieldLength      = spkt.LineLen
	DefaultHopFExpiry   = 63
	MacLen              = 3
)

func NewHopField(b util.RawBytes, in IntfID, out IntfID) *HopField {
	h := &HopField{}
	h.data = b
	h.ExpTime = DefaultHopFExpiry
	h.Ingress = in
	h.Egress = out
	h.Write()
	return h
}

func HopFFromRaw(b []byte) (*HopField, *util.Error) {
	if len(b) < HopFieldLength {
		return nil, util.NewError(ErrorHopFTooShort, "min", spkt.LineLen, "actual", len(b))
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
	h.Ingress = IntfID(h.data[offset]<<4 | h.data[offset+1]>>4)
	h.Egress = IntfID((h.data[offset+1]&0xF)<<4 | h.data[offset+2])
	offset += 3
	h.Mac = h.data[offset:]
	return h, nil
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

func (h *HopField) Verify(block cipher.Block, tsInt uint32, prev util.RawBytes) *util.Error {
	if mac, err := h.CalcMac(block, tsInt, prev); err != nil {
		return err
	} else if !bytes.Equal(h.Mac, mac) {
		return util.NewError(ErrorHopFBadMac, "expected", h.Mac, "actual", mac)
	}
	return nil
}

func (h *HopField) CalcMac(block cipher.Block, tsInt uint32,
	prev util.RawBytes) (util.RawBytes, *util.Error) {
	all := make(util.RawBytes, macInputLen)
	order.PutUint32(all, tsInt)
	all[4] = h.data[0] & HopFieldVerifyFlags
	copy(all[5:], h.data[1:5])
	copy(all[9:], prev)
	mac, err := util.CBCMac(block, all)
	return mac[:MacLen], err
}
