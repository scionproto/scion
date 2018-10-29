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

package rpkt

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
)

const (
	UnsupportedL4 = "Unsupported L4 header type"
)

// L4Hdr finds, parses and returns the layer 4 header, if any. The verify
// argument determines whether to verify the L4 header or not.
func (rp *RtrPkt) L4Hdr(verify bool) (l4.L4Header, error) {
	if rp.l4 == nil {
		// First, find if there is an L4 header.
		if found, err := rp.findL4(); !found || err != nil {
			return nil, err
		}
		switch rp.L4Type {
		case common.L4SCMP:
			scmpHdr, err := scmp.HdrFromRaw(rp.Raw[rp.idxs.l4:])
			if err != nil {
				return nil, err
			}
			rp.l4 = scmpHdr
			rp.idxs.pld = rp.idxs.l4 + scmp.HdrLen
		case common.L4UDP:
			udp, err := l4.UDPFromRaw(rp.Raw[rp.idxs.l4:])
			if err != nil {
				return nil, err
			}
			rp.l4 = udp
			rp.idxs.pld = rp.idxs.l4 + l4.UDPLen
		/*
			case common.L4TCP:
				rp.l4 = &l4.TCP{}
		*/
		default:
			// Can't return an SCMP error as we don't understand the L4 header
			return nil, common.NewBasicError(UnsupportedL4, nil, "type", rp.L4Type)
		}
	}
	if verify {
		if err := rp.verifyL4(); err != nil {
			return nil, err
		}
	}
	return rp.l4, nil
}

// findL4 tries to find the layer 4 header, if any.
func (rp *RtrPkt) findL4() (bool, error) {
	// Start from the next unparsed header, if any.
	nextHdr := rp.idxs.nextHdrIdx.Type
	offset := rp.idxs.nextHdrIdx.Index
	for nextHdr == common.HopByHopClass || nextHdr == common.End2EndClass {
		if len(rp.Raw[offset:]) < common.LineLen {
			return false, common.NewBasicError("Bad header length", nil,
				"min", common.LineLen, "actual", len(rp.Raw[offset:]))
		}
		currHdr := nextHdr
		currExtn := common.ExtnType{Class: currHdr, Type: rp.Raw[offset+2]}
		if currHdr == common.HopByHopClass {
			rp.idxs.hbhExt = append(rp.idxs.hbhExt, extnIdx{currExtn, offset})
		} else {
			rp.idxs.e2eExt = append(rp.idxs.e2eExt, extnIdx{currExtn, offset})
		}
		nextHdr = common.L4ProtocolType(rp.Raw[offset])
		hdrLen := int(rp.Raw[offset+1]) * common.LineLen
		if hdrLen == 0 {
			// FIXME(kormat): Can't return an SCMP error as we can't parse the headers
			return false, common.NewBasicError("0-length header", nil,
				"currHdr", currHdr, "nextHdr", nextHdr, "offset", offset)
		}
		offset += hdrLen
		if offset > len(rp.Raw) {
			// FIXME(kormat): Can't generally return an SCMP error as parsing the
			// headers has failed.
			return false, common.NewBasicError(ErrExtChainTooLong, nil,
				"curr", offset, "max", len(rp.Raw))
		}
		rp.idxs.nextHdrIdx.Type = nextHdr
		rp.idxs.nextHdrIdx.Index = offset
	}
	// Reached L4 Protocol
	rp.L4Type = nextHdr
	rp.idxs.l4 = offset
	return true, nil
}

// verifyL4 verifies that the layer 4 header's contents and checksum are correct.
func (rp *RtrPkt) verifyL4() error {
	if err := rp.l4.Validate(len(rp.Raw[rp.idxs.pld:])); err != nil {
		return err
	}
	if err := rp.verifyL4Chksum(); err != nil {
		return err
	}
	return nil
}

// verifyL4Chksum calculates the appropriate checksum for the layer 4 header,
// and verifies that it matches the one supplied in the l4 header.
func (rp *RtrPkt) verifyL4Chksum() error {
	switch h := rp.l4.(type) {
	case *l4.UDP, *scmp.Hdr:
		addr, pld := rp.getChksumInput()
		if err := l4.CheckCSum(h, addr, pld); err != nil {
			return err
		}
	default:
		rp.Debug("Skipping checksum verification of L4 header", "type", rp.L4Type)
	}
	return nil
}

// getChksumInput is a helper method to return the raw bytes of the address
// header (excluding padding) and the payload, for calculating a
// layer 4 checksum.
func (rp *RtrPkt) getChksumInput() (ahdr, pld common.RawBytes) {
	dstLen, _ := addr.HostLen(rp.CmnHdr.DstType)
	srcLen, _ := addr.HostLen(rp.CmnHdr.SrcType)
	addrsLen := int(addr.IABytes*2 + dstLen + srcLen)
	ahdr = rp.Raw[rp.idxs.dstIA : rp.idxs.dstIA+addrsLen]
	pld = rp.Raw[rp.idxs.pld:]
	return
}

// updateL4 handles updating the layer 4 header after the payload has been set
// (or changed).
func (rp *RtrPkt) updateL4() error {
	switch h := rp.l4.(type) {
	case *l4.UDP, *scmp.Hdr:
		addr, pld := rp.getChksumInput()
		h.SetPldLen(len(pld))
		if err := l4.SetCSum(h, addr, pld); err != nil {
			return err
		}
		if err := h.Write(rp.Raw[rp.idxs.l4:]); err != nil {
			return err
		}
	default:
		return common.NewBasicError("Updating l4 payload not supported", nil, "type", rp.L4Type)
	}
	return nil
}
