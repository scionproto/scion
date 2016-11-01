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
	"bytes"
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	ErrorL4Unsupported   = "Unsupported L4 header type"
	ErrorL4InvalidChksum = "Invalid L4 checksum"
)

type L4Header interface {
	fmt.Stringer
}

func (rp *RPkt) L4Hdr() (L4Header, *util.Error) {
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
			rp.l4 = &l4.SSP{}
		case common.L4TCP:
			rp.l4 = &l4.TCP{}
		default:
			return nil, util.NewError(ErrorL4Unsupported, "type", rp.L4Type)
		}
	}
	if err := rp.verifyL4Chksum(); err != nil {
		return nil, err
	}
	return rp.l4, nil
}

func (rp *RPkt) findL4() (bool, *util.Error) {
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
	}
	if offset > len(rp.Raw) {
		return false, util.NewError(ErrorExtChainTooLong, "curr", offset, "max", len(rp.Raw))
	}
	rp.idxs.nextHdrIdx.Type = nextHdr
	rp.idxs.nextHdrIdx.Index = offset
	return true, nil
}

func (rp *RPkt) verifyL4Chksum() *util.Error {
	switch v := rp.l4.(type) {
	case *l4.UDP:
		src, dst, pld := rp.getChksumInput()
		if csum, err := v.CalcChecksum(src, dst, pld); err != nil {
			return err
		} else if bytes.Compare(v.Checksum, csum) != 0 {
			return util.NewError(ErrorL4InvalidChksum,
				"expected", v.Checksum, "actual", csum, "proto", rp.L4Type)
		}
	case *scmp.Hdr:
		src, dst, pld := rp.getChksumInput()
		if csum, err := v.CalcChecksum(src, dst, pld); err != nil {
			return err
		} else if bytes.Compare(v.Checksum, csum) != 0 {
			return util.NewError(ErrorL4InvalidChksum,
				"expected", v.Checksum, "actual", csum, "proto", rp.L4Type)
		}
	default:
		rp.Debug("Skipping checksum verification of L4 header", "type", rp.L4Type)
	}
	return nil
}

func (rp *RPkt) getChksumInput() (src, dst, pld util.RawBytes) {
	srcLen, _ := addr.HostLen(rp.CmnHdr.SrcType)
	dstLen, _ := addr.HostLen(rp.CmnHdr.DstType)
	src = rp.Raw[rp.idxs.srcIA : rp.idxs.srcIA+addr.IABytes+int(srcLen)]
	dst = rp.Raw[rp.idxs.dstIA : rp.idxs.dstIA+addr.IABytes+int(dstLen)]
	pld = rp.Raw[rp.idxs.pld:]
	return
}

func (rp *RPkt) updateL4() *util.Error {
	switch v := rp.l4.(type) {
	case *l4.UDP:
		src, dst, pld := rp.getChksumInput()
		v.SetPldLen(len(pld))
		csum, err := v.CalcChecksum(src, dst, pld)
		if err != nil {
			return err
		}
		v.Checksum = csum
		rawUdp, err := v.Pack()
		if err != nil {
			return err
		}
		copy(rp.Raw[rp.idxs.l4:], rawUdp)
	default:
		return util.NewError("Updating l4 payload not supported", "type", rp.L4Type)
	}
	return nil
}
