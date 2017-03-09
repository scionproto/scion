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

// This file handles packet processing.

package rpkt

import (
	"bytes"
	"crypto/cipher"
	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
	"time"
)

const currINFOffset = 5
const currHFOffset = 6

// Return type of router.PutSCMPAuthDRKeyRequest
type SCMPAuthPutResult int

const (
	// Packet buffered. Request forwarded.
	SCMPAuthSuccess SCMPAuthPutResult = iota
	// Packet not buffered. Request forwarded.
	SCMPAuthPktQueueFull
	// Packet not buffered. Request not forwarded.
	SCMPAuthDRKeyQueueFull
	// Packet not buffered. Request not forwarded.
	SCMPAuthChannelBlocking
	// Packet not buffered. Request forwarded.
	SCMPAuthNoPktQueueAvailable
	// Packet not buffered. Request forwarded.
	SCMPAuthPktQueueFreed
)

type SCMPAuthCallbacks struct {
	// Handler from the router to handle responses from the local CS.
	ReplyHandler func(proto.ScmpAuthLocalRep)
	// Callback to request SCMPAuth DRKey and buffer packet.
	RequestF func(*addr.ISD_AS, *RtrPkt) SCMPAuthPutResult
	// Store for SCMPAuth DRKeys.
	DRKeys *SCMPAuthDRKeys
	// Store for SCMPAuth DRKey requests and packet buffer.
	MissingDRKeys *MissingSCMPAuthDRKeys
}

var scmpAuthCallbacks *SCMPAuthCallbacks

type scmpAuthExtnHolder struct {
	SCMPAuthDRKey       *rSecurityExt
	SCMPAuthHashedDRKey *rSecurityExt
	SCMPAuthHashTree    *rSecurityExt
}

// processSCMPAuth is a processing hook to sign/verify the SCMP messages at the border router
// This hook shall only be inserted, if this IA is srcIA or dstIA
// IMPORTANT: HashTree SCMPAuth not supported yet.
func (rp *RtrPkt) ProcessSCMPAuthExt() (HookResult, *common.Error) {
	scmpAuthExtns, e := rp.findSCMPAuthExtns()
	if e != nil {
		return HookError, e
	}

	switch {
	case rp.DirFrom == DirLocal || rp.DirFrom == DirSelf: /* && rp.DirTo != DirLocal TODO(roosd): uncomment, is used for testing in local AS*/
		return rp.signSCMPAuthExtns(scmpAuthExtns)
	case (rp.DirTo == DirLocal || rp.DirTo == DirSelf) && (rp.DirFrom != DirLocal || rp.DirFrom != DirSelf):
		return rp.verifySCMPAuthExtns(scmpAuthExtns)
	}
	return HookContinue, nil
}

// signSCMPAuthExtns computes the MAC/signature and inserts them into the extensions.
func (rp *RtrPkt) signSCMPAuthExtns(scmpAuthExtns *scmpAuthExtnHolder) (HookResult, *common.Error) {
	// Zero INF and HF.
	inf, hf, hl := rp.readFields()
	rp.setFields(0, 0, 0)
	defer rp.setFields(inf, hf, hl)

	if scmpAuthExtns.SCMPAuthDRKey != nil {
		timestamp := make(common.RawBytes, 4)
		common.Order.PutUint32(timestamp, uint32(time.Now().Unix()))
		scmpAuthExtns.SCMPAuthDRKey.UpdateTimeStamp(timestamp)
		scmpAuthExtns.SCMPAuthDRKey.ResetMac()
	}

	if scmpAuthExtns.SCMPAuthDRKey != nil {
		timestamp := make(common.RawBytes, 4)
		common.Order.PutUint32(timestamp, uint32(time.Now().Unix()))
		scmpAuthExtns.SCMPAuthDRKey.UpdateTimeStamp(timestamp)
		scmpAuthExtns.SCMPAuthDRKey.ResetMac()
	}

	if scmpAuthExtns.SCMPAuthHashTree != nil {
		// TODO(roosd): implement
	}

	if scmpAuthExtns.SCMPAuthDRKey != nil || scmpAuthExtns.SCMPAuthHashedDRKey != nil {
		var mac, macHashed common.RawBytes

		// Get block
		block, e := rp.getSCMPAuthDRKeyBlock(rp.calcSCMPAuthDRKey())
		if e != nil {
			return HookError, e
		}

		// Calculate MACs
		if scmpAuthExtns.SCMPAuthDRKey != nil {
			if mac, e = rp.CalcSCMPAuthMac(block); e != nil {
				return HookError, e
			}
		}

		if scmpAuthExtns.SCMPAuthHashedDRKey != nil {
			if macHashed, e = rp.calcHashedSCMPMac(block, scmpAuthExtns.SCMPAuthHashedDRKey.PktHash()); e != nil {
				return HookError, e
			}
		}

		// Set MACs
		if scmpAuthExtns.SCMPAuthDRKey != nil {
			copy(scmpAuthExtns.SCMPAuthDRKey.MAC(), mac)
		}

		if scmpAuthExtns.SCMPAuthHashedDRKey != nil {
			copy(scmpAuthExtns.SCMPAuthHashedDRKey.MAC(), macHashed)
		}

	}

	// TODO(roosd): Implement handling SCMP_AUTH_HASH_TREE

	if scmpAuthExtns.SCMPAuthDRKey == nil && scmpAuthExtns.SCMPAuthHashedDRKey == nil && scmpAuthExtns.SCMPAuthHashTree == nil {
		// FIXME(roosd): When being deployed, a packet shall be dropped if no SCMPAuth header is provided. Needs adaption of the end hosts.
		rp.Warn("Packet did not provide a SCMPAuth header")
	}
	return HookContinue, nil
}

// verifySCMPAuthExtns verifies the MAC and drops packet if non matching.
func (rp *RtrPkt) verifySCMPAuthExtns(scmpAuthExtns *scmpAuthExtnHolder) (HookResult, *common.Error) {

	if scmpAuthExtns.SCMPAuthDRKey != nil || scmpAuthExtns.SCMPAuthHashedDRKey != nil {

		// Fetch DRKey
		scmpAuthCallbacks.DRKeys.RLock()
		drkey, ok := scmpAuthCallbacks.DRKeys.Map[rp.srcIA.Uint32()]
		scmpAuthCallbacks.DRKeys.RUnlock()

		if ok {
			var origMac, origHashedMac common.RawBytes
			// Zero INF and HF.
			inf, hf, hl := rp.readFields()
			rp.setFields(0, 0, 0)
			defer rp.setFields(inf, hf, hl)

			if scmpAuthExtns.SCMPAuthDRKey != nil {
				origMac = make(common.RawBytes, len(scmpAuthExtns.SCMPAuthDRKey.MAC()))
				copy(origMac, scmpAuthExtns.SCMPAuthDRKey.MAC())
				scmpAuthExtns.SCMPAuthDRKey.ResetMac()
				defer copy(scmpAuthExtns.SCMPAuthDRKey.MAC(), origMac)
			}

			if scmpAuthExtns.SCMPAuthHashedDRKey != nil {
				origHashedMac = make(common.RawBytes, len(scmpAuthExtns.SCMPAuthHashedDRKey.MAC()))
				copy(origHashedMac, scmpAuthExtns.SCMPAuthHashedDRKey.MAC())
				scmpAuthExtns.SCMPAuthHashedDRKey.ResetMac()
				defer copy(scmpAuthExtns.SCMPAuthHashedDRKey.MAC(), origHashedMac)
			}

			block, e := rp.getSCMPAuthDRKeyBlock(drkey, nil)
			if e != nil {
				return HookError, e
			}

			if scmpAuthExtns.SCMPAuthDRKey != nil {
				mac, e := rp.CalcSCMPAuthMac(block)
				if e != nil {
					return HookError, e
				}
				if !bytes.Equal(mac, origMac) {
					return HookError, common.NewError("SCMPAuthDRKeyMac does not match.",
						"Original MAC", origMac, "Computed MAC", mac)
				}
			}

			if scmpAuthExtns.SCMPAuthHashedDRKey != nil {
				// TODO(roosd). replace
				hash := make(common.RawBytes, len(scmpAuthExtns.SCMPAuthHashedDRKey.PktHash()))
				if !bytes.Equal(hash, scmpAuthExtns.SCMPAuthHashedDRKey.PktHash()) {
					return HookError, common.NewError("SCMPAuthHashedDRKey hash does not match.",
						"Original hash", scmpAuthExtns.SCMPAuthHashedDRKey.PktHash(),
						"Computed hash", hash)
				}
				mac, e := rp.calcHashedSCMPMac(block, hash)
				if e != nil {
					return HookError, e
				}
				if !bytes.Equal(mac, origHashedMac) {
					return HookError, common.NewError("SCMPAuthHashedDRKeyMac does not match.",
						"Original MAC", origHashedMac, "Computed MAC", mac)
				}
			}

		} else {
			scmpAuthCallbacks.RequestF(rp.srcIA, rp)
			return HookError, common.NewError("SCMPAuthDRKey not present. Packet is buffered.")
		}
	}

	if scmpAuthExtns.SCMPAuthDRKey == nil && scmpAuthExtns.SCMPAuthHashedDRKey == nil && scmpAuthExtns.SCMPAuthHashTree == nil {
		// FIXME(roosd): When being deployed, a packet shall be dropped if no SCMPAuth header is provided. Needs adaption of the end hosts.
		rp.Warn("Packet did not provide a SCMPAuth header")
	}
	return HookContinue, nil
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
			if secMode == spkt.SCMP_AUTH_DRKEY || secMode == spkt.SCMP_AUTH_HASHED_DRKEY || secMode == spkt.SCMP_AUTH_HASH_TREE {
				ext, err := rSecurityExtFromRaw(rp, *offset+common.ExtnSubHdrLen, *offset+hdrLen)
				if err != nil {
					return nil, err
				}

				switch ext.SecMode {
				case spkt.SCMP_AUTH_DRKEY:
					if scmpAuthEtxns.SCMPAuthDRKey != nil {
						return nil, common.NewError("Multiple SCMPAuthDRKeyExtensions.")
					}
					scmpAuthEtxns.SCMPAuthDRKey = ext
				case spkt.SCMP_AUTH_HASHED_DRKEY:
					if scmpAuthEtxns.SCMPAuthHashedDRKey != nil {
						return nil, common.NewError("Multiple SCMPAuthHashedDRKeyExtensions.")
					}
					scmpAuthEtxns.SCMPAuthHashedDRKey = ext
				case spkt.SCMP_AUTH_HASH_TREE:
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
	DRKeyAuthBlock, e := util.InitAES(drkey)
	if e != nil {
		return nil, e
	}
	return DRKeyAuthBlock, nil
}

// calcSCMPAuthDRKey calculates the SCMPAuth DRKey for this packet.
func (rp *RtrPkt) calcSCMPAuthDRKey() (common.RawBytes, *common.Error) {
	all := make(common.RawBytes, 16)
	common.Order.PutUint32(all, uint32(rp.dstIA.I))
	common.Order.PutUint32(all[4:], uint32(rp.dstIA.A))
	mac, err := util.CBCMac(conf.SCMPAuth.AESBlock, all)
	return mac, err
}

// CalcSCMPAuthMac calculates the SCMPAuthMac for his packet.
// The SCMPAuthExtns are assumed to be set appropriately and bytes 4-6 are zeroed.
func (rp *RtrPkt) CalcSCMPAuthMac(block cipher.Block) (common.RawBytes, *common.Error) {
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

// calcHashedSCMPMac calculates the hashed SCMPAuthMac for his packet.
// The SCMPAuthExtns are assumed to be set appropriately and bytes 4-6 are zeroed.
func (rp *RtrPkt) calcHashedSCMPMac(block cipher.Block, hash common.RawBytes) (common.RawBytes, *common.Error) {
	mac := make(common.RawBytes, len(hash))
	copy(mac, hash)
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
