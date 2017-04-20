// Copyright 2017 ETH Zurich
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

// This file handles packet processing.

package rpkt

import (
	"crypto/cipher"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sec_extn"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const currINFOffset = 5
const currHFOffset = 6

type scmpAuthExtnHolder struct {
	SCMPAuthDRKey    *rSecurityExt
	SCMPAuthHashTree *rSecurityExt
}

// AuthenticateSCMPAuthExt computes the MAC and inserts it into the extensions.
func (rp *RtrPkt) AuthenticateSCMPAuthExt() *common.Error {
	scmpAuthExtns, e := rp.findSCMPAuthExtns()
	if e != nil {
		return e
	}

	// Zero INF and HF.
	inf, hf, hl := rp.readFields()
	rp.setFields(0, 0, 0)
	defer rp.setFields(inf, hf, hl)

	if scmpAuthExtns.SCMPAuthDRKey == nil {
		return common.NewError("No SCMPAuthDRKey extension found.")
	}
	scmpAuthExtns.SCMPAuthDRKey.ResetMac()
	block, e := rp.getSCMPAuthDRKeyBlock(rp.calcSCMPAuthDRKey())
	if e != nil {
		return e
	}
	if mac, e := rp.calcSCMPAuthMac(block); e != nil {
		return e
	} else {
		copy(scmpAuthExtns.SCMPAuthDRKey.MAC(), mac)
	}

	return nil
}

// findSCMPAuthExtns walks the header chain, searching for SCMPAuth extensions.
// It returns a scmpAuthExtnHolder, with the appropriate pointers to the extensions.
func (rp *RtrPkt) findSCMPAuthExtns() (*scmpAuthExtnHolder, *common.Error) {
	scmpAuthEtxns := &scmpAuthExtnHolder{}
	var Index int
	var Type common.L4ProtocolType

	if len(rp.idxs.hbhExt) > 0 {
		lastHBHExt := rp.idxs.hbhExt[len(rp.idxs.hbhExt)-1]
		Index = lastHBHExt.Index
		Type = common.L4ProtocolType(rp.Raw[Index])
	} else {
		Index = int(rp.CmnHdr.HdrLen)
		Type = rp.CmnHdr.NextHdr
	}

	offset := &Index
	nextHdr := &Type

	for *offset < len(rp.Raw) {
		currHdr := *nextHdr
		if currHdr != common.End2EndClass && currHdr != common.HopByHopClass { // Reached L4 protocol
			break
		}
		hdrLen := int((rp.Raw[*offset+1] + 1) * common.LineLen)
		if rp.Raw[*offset+2] == common.ExtnSecurityType.Type {
			secMode := rp.Raw[*offset+common.ExtnSubHdrLen]
			if secMode == sec_extn.SCMP_AUTH_DRKEY || secMode == sec_extn.SCMP_AUTH_HASH_TREE {
				ext, err := rSecurityExtFromRaw(rp, *offset+common.ExtnSubHdrLen, *offset+hdrLen)
				if err != nil {
					return nil, err
				}

				switch ext.SecMode {
				case sec_extn.SCMP_AUTH_DRKEY:
					if scmpAuthEtxns.SCMPAuthDRKey != nil {
						return nil, common.NewError("Multiple SCMPAuthDRKeyExtensions.")
					}
					scmpAuthEtxns.SCMPAuthDRKey = ext
				case sec_extn.SCMP_AUTH_HASH_TREE:
					if scmpAuthEtxns.SCMPAuthHashTree != nil {
						return nil, common.NewError("Multiple SCMPAuthHashTreeExtensions.")
					}
					scmpAuthEtxns.SCMPAuthHashTree = ext
				}
			}
		}
		*nextHdr = common.L4ProtocolType(rp.Raw[*offset])
		*offset += hdrLen
	}
	if *offset > len(rp.Raw) {
		return nil, common.NewError(errExtChainTooLong, "curr", offset, "max", len(rp.Raw))
	}
	return scmpAuthEtxns, nil
}

// getSCMPAuthDRKeyBlock returns a cipher block for the given DRKey
func (rp *RtrPkt) getSCMPAuthDRKeyBlock(drkey common.RawBytes, e *common.Error) (cipher.Block, *common.Error) {
	if e != nil {
		return nil, e
	}
	return util.InitAES(drkey)
}

// calcSCMPAuthDRKey calculates the SCMPAuth DRKey for this packet.
func (rp *RtrPkt) calcSCMPAuthDRKey() (common.RawBytes, *common.Error) {
	in := make(common.RawBytes, 16)
	common.Order.PutUint32(in, uint32(rp.dstIA.I))
	common.Order.PutUint32(in[4:], uint32(rp.dstIA.A))
	blockFstOrder, e := rp.getSCMPAuthDRKeyBlock(util.CBCMac(conf.C.DRKeyAESBlock, in))
	if e != nil {
		return nil, e
	}

	in = make(common.RawBytes, 32)
	rp.dstIA.Write(in)
	copy(in[4:], rp.dstHost.Pack())
	copy(in[20:], []byte("SCMP"))
	return util.CBCMac(blockFstOrder, in)
}

// CalcSCMPAuthMac calculates the SCMPAuthMac for his packet.
// The SCMPAuthExtns are assumed to be set appropriately and bytes 4-6 are zeroed.
func (rp *RtrPkt) calcSCMPAuthMac(block cipher.Block) (common.RawBytes, *common.Error) {
	blkSize := block.BlockSize()
	numBlocks := len(rp.Raw) / blkSize
	if len(rp.Raw)%blkSize != 0 {
		numBlocks++
	}

	mac := make(common.RawBytes, numBlocks*blkSize)
	copy(mac, rp.Raw)
	mac, e := util.CBCMac(block, mac)

	return mac, e
}

// readFields reads fields of the packet, which will be set to zero.
func (rp *RtrPkt) readFields() (uint8, uint8, uint8) {
	return rp.Raw[currINFOffset], rp.Raw[currHFOffset], rp.Raw[4]
}

// setFields sets the fields to given value.
func (rp *RtrPkt) setFields(inf uint8, hf uint8, hl uint8) {
	rp.Raw[currINFOffset] = inf
	rp.Raw[currHFOffset] = hf
	rp.Raw[4] = hl
}
