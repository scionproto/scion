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
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/scmp"
)

const (
	ErrorL4Unsupported = "Unsupported L4 header type"
)

func (rp *RtrPkt) L4Hdr(verify bool) (l4.L4Header, *common.Error) {
	if rp.l4 == nil {
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
		case common.L4SSP:
			//rp.l4 = &l4.SSP{}
		case common.L4TCP:
			//rp.l4 = &l4.TCP{}
		default:
			// Can't return an SCMP error as we don't understand the L4 header
			return nil, common.NewError(ErrorL4Unsupported, "type", rp.L4Type)
		}
	}
	if verify {
		if err := rp.verifyL4(); err != nil {
			return nil, err
		}
	}
	return rp.l4, nil
}

func (rp *RtrPkt) findL4() (bool, *common.Error) {
	nextHdr := rp.idxs.nextHdrIdx.Type
	offset := rp.idxs.nextHdrIdx.Index
	for offset < len(rp.Raw) {
		currHdr := nextHdr
		_, ok := common.L4Protocols[currHdr]
		if ok { // Reached L4 protocol
			rp.L4Type = nextHdr
			rp.idxs.l4 = offset
			break
		}
		currExtn := common.ExtnType{Class: currHdr, Type: rp.Raw[offset+2]}
		hdrLen := int((rp.Raw[offset+1] + 1) * common.LineLen)
		rp.idxs.e2eExt = append(rp.idxs.e2eExt, extnIdx{currExtn, offset})
		nextHdr = common.L4ProtocolType(rp.Raw[offset])
		offset += hdrLen
		if hdrLen == 0 {
			// Can't return an SCMP error as we can't parse the headers
			return false, common.NewError("0-length header", "nextHdr", nextHdr, "offset", offset)
		}
	}
	if offset > len(rp.Raw) {
		// Can't generally return an SCMP error as parsing the headers has failed.
		return false, common.NewError(ErrorExtChainTooLong, "curr", offset, "max", len(rp.Raw))
	}
	rp.idxs.nextHdrIdx.Type = nextHdr
	rp.idxs.nextHdrIdx.Index = offset
	return true, nil
}

func (rp *RtrPkt) verifyL4() *common.Error {
	if err := rp.l4.Validate(len(rp.Raw[rp.idxs.pld:])); err != nil {
		return err
	}
	if err := rp.verifyL4Chksum(); err != nil {
		return err
	}
	return nil
}

func (rp *RtrPkt) verifyL4Chksum() *common.Error {
	switch h := rp.l4.(type) {
	case *l4.UDP, *scmp.Hdr:
		src, dst, pld := rp.getChksumInput()
		if err := l4.CheckCSum(h, src, dst, pld); err != nil {
			return err
		}
	default:
		rp.Debug("Skipping checksum verification of L4 header", "type", rp.L4Type)
	}
	return nil
}

func (rp *RtrPkt) getChksumInput() (src, dst, pld common.RawBytes) {
	srcLen, _ := addr.HostLen(rp.CmnHdr.SrcType)
	dstLen, _ := addr.HostLen(rp.CmnHdr.DstType)
	src = rp.Raw[rp.idxs.srcIA : rp.idxs.srcIA+addr.IABytes+int(srcLen)]
	dst = rp.Raw[rp.idxs.dstIA : rp.idxs.dstIA+addr.IABytes+int(dstLen)]
	pld = rp.Raw[rp.idxs.pld:]
	return
}

func (rp *RtrPkt) updateL4() *common.Error {
	switch h := rp.l4.(type) {
	case *l4.UDP, *scmp.Hdr:
		src, dst, pld := rp.getChksumInput()
		h.SetPldLen(len(pld))
		if err := l4.SetCSum(h, src, dst, pld); err != nil {
			return err
		}
		if err := h.Write(rp.Raw[rp.idxs.l4:]); err != nil {
			return err
		}
	default:
		return common.NewError("Updating l4 payload not supported", "type", rp.L4Type)
	}
	return nil
}
