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

// This file handles the creation of RtrPkt.

package rpkt

import (
	"time"

	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/spkt"
)

// RtrPktFromScnPkt creates an RtrPkt from an spkt.ScnPkt.
func RtrPktFromScnPkt(sp *spkt.ScnPkt, ctx *rctx.Ctx) (*RtrPkt, error) {
	rp := NewRtrPkt()
	rp.Ctx = ctx
	totalLen := sp.TotalLen()
	hdrLen := sp.HdrLen() / common.LineLen
	rp.TimeIn = time.Now()
	rp.Id = log.RandId(4)
	rp.Logger = log.New("rpkt", rp.Id)
	rp.DirFrom = rcmn.DirSelf
	// Fill in common header.
	rp.CmnHdr.DstType = sp.DstHost.Type()
	rp.CmnHdr.SrcType = sp.SrcHost.Type()
	rp.CmnHdr.TotalLen = uint16(totalLen) // Updated later as necessary.
	rp.CmnHdr.HdrLen = uint8(hdrLen)
	rp.CmnHdr.CurrInfoF = 0           // Updated later as necessary.
	rp.CmnHdr.CurrHopF = 0            // Updated later as necessary.
	rp.CmnHdr.NextHdr = common.L4None // Updated later as necessary.
	// Fill in address header and indexes.
	rp.idxs.dstIA = spkt.CmnHdrLen
	rp.dstIA = sp.DstIA
	rp.idxs.srcIA = rp.idxs.dstIA + addr.IABytes
	rp.srcIA = sp.SrcIA
	rp.idxs.dstHost = rp.idxs.srcIA + addr.IABytes
	rp.dstHost = sp.DstHost
	rp.idxs.srcHost = rp.idxs.dstHost + rp.dstHost.Size()
	rp.srcHost = sp.SrcHost
	rp.dstIA.Write(rp.Raw[rp.idxs.dstIA:])
	rp.srcIA.Write(rp.Raw[rp.idxs.srcIA:])
	copy(rp.Raw[rp.idxs.dstHost:], rp.dstHost.Pack())
	copy(rp.Raw[rp.idxs.srcHost:], rp.srcHost.Pack())
	// Fill in path
	rp.idxs.path = spkt.CmnHdrLen + sp.AddrLen()
	if sp.Path != nil {
		copy(rp.Raw[rp.idxs.path:], sp.Path.Raw)
		rp.CmnHdr.CurrInfoF = uint8((rp.idxs.path + sp.Path.InfOff) / common.LineLen)
		rp.CmnHdr.CurrHopF = uint8((rp.idxs.path + sp.Path.HopOff) / common.LineLen)
	}
	// Fill in extensions
	// rp.idxs.l4 Will be updated as necessary by extnAddHBH and extnAddE2E
	rp.idxs.l4 = int(hdrLen) * common.LineLen
	for _, se := range sp.HBHExt {
		if err := rp.extnAddHBH(se); err != nil {
			return nil, err
		}
	}
	for _, se := range sp.E2EExt {
		if err := rp.extnAddE2E(se); err != nil {
			return nil, err
		}
	}
	// Fill in L4 Header
	rp.idxs.pld = int(hdrLen) * common.LineLen // Will be updated as necessary by addL4
	if sp.L4 != nil {
		if err := rp.addL4(sp.L4); err != nil {
			return nil, err
		}
		// Fill in payload
		if err := rp.SetPld(sp.Pld); err != nil {
			return nil, err
		}
	} else {
		// Trim buffer to the end of the last extension header (or path header,
		// if there are no extensions), and write common header into buffer.
		rp.Raw = rp.Raw[:rp.idxs.l4]
		rp.CmnHdr.TotalLen = uint16(len(rp.Raw))
		rp.CmnHdr.Write(rp.Raw)
	}
	if _, err := rp.InfoF(); err != nil {
		return nil, err
	}
	if _, err := rp.ConsDirFlag(); err != nil {
		return nil, err
	}
	return rp, nil
}

// addL4 adds a layer 4 header to an RtrPkt during creation.
func (rp *RtrPkt) addL4(l4h l4.L4Header) error {
	rp.L4Type = l4h.L4Type()
	rp.l4 = l4h
	// Reset buffer to full size
	rp.Raw = rp.Raw[:cap(rp.Raw)]
	// Write L4 header into buffer
	if err := rp.l4.Write(rp.Raw[rp.idxs.l4:]); err != nil {
		return err
	}
	// Locate the last extension in the packet, whether HBH (hop-by-hop) or E2E (end-to-end),
	// so that its sub-header can be updated with the L4 prototcol type.
	rp.idxs.pld = rp.idxs.l4 + l4h.L4Len()
	var nextHdr *uint8
	for _, eIdx := range rp.idxs.hbhExt {
		nextHdr = &rp.Raw[eIdx.Index]
	}
	for _, eIdx := range rp.idxs.e2eExt {
		nextHdr = &rp.Raw[eIdx.Index]
	}
	if nextHdr != nil {
		// Last extension sub-header found, update its nextHdr field.
		*nextHdr = uint8(rp.L4Type)
	} else {
		// There are no extensions, so the common header NextHDr field needs to be updated.
		rp.CmnHdr.NextHdr = rp.L4Type
	}
	// Trim buffer to the end of the L4 header, and write common header into buffer.
	rp.Raw = rp.Raw[:rp.idxs.pld]
	rp.CmnHdr.TotalLen = uint16(len(rp.Raw))
	rp.CmnHdr.Write(rp.Raw)
	return nil
}

// SetPld updates/sets the payload of an RtrPkt.
func (rp *RtrPkt) SetPld(pld common.Payload) error {
	rp.pld = pld
	var plen int
	if rp.pld != nil {
		// Reset buffer to full size
		rp.Raw = rp.Raw[:cap(rp.Raw)]
		// Write payload into buffer
		var err error
		if plen, err = rp.pld.WritePld(rp.Raw[rp.idxs.pld:]); err != nil {
			return err
		}
	}
	// Trim buffer to the end of the payload.
	rp.Raw = rp.Raw[:rp.idxs.pld+plen]
	// Update L4 header
	if err := rp.updateL4(); err != nil {
		return err
	}
	// Write common header into buffer.
	rp.CmnHdr.TotalLen = uint16(len(rp.Raw))
	rp.CmnHdr.Write(rp.Raw)
	return nil
}

// CreateReplyScnPkt creates a generic ScnPkt reply, by converting the RtrPkt
// to an ScnPkt, then reversing the ScnPkt, and setting the reply source address.
func (rp *RtrPkt) CreateReplyScnPkt() (*spkt.ScnPkt, error) {
	sp, err := rp.ToScnPkt(false)
	if err != nil {
		return nil, err
	}
	if err = sp.Reverse(); err != nil {
		return nil, err
	}
	sp.SrcIA = rp.Ctx.Conf.IA
	// Use the local address as the source host
	pub := rp.Ctx.Conf.Net.LocAddr.PublicOverlay(rp.Ctx.Conf.Topo.Overlay)
	sp.SrcHost = pub.L3()
	return sp, nil
}

func (rp *RtrPkt) CreateReply(sp *spkt.ScnPkt) (*RtrPkt, error) {
	// Convert back to RtrPkt
	reply, err := RtrPktFromScnPkt(sp, rp.Ctx)
	if err != nil {
		return nil, err
	}
	dstIA, err := reply.DstIA()
	if err != nil {
		return nil, err
	}
	// Only (potentially) call IncPath if the dest is not in the local AS.
	if !dstIA.Equal(rp.Ctx.Conf.IA) {
		hopF, err := reply.HopF()
		if err != nil {
			return nil, err
		}
		if hopF != nil && hopF.Xover {
			// Always increment reversed path on a xover point.
			if _, err := reply.IncPath(); err != nil {
				return nil, err
			}
			// Increment reversed path if it was incremented in the forward direction.
			// Check
			// https://github.com/scionproto/scion/blob/master/doc/PathReversal.md
			// for details.
			if rp.IncrementedPath {
				if _, err := reply.IncPath(); err != nil {
					return nil, err
				}
			}
		} else if rp.DirFrom == rcmn.DirExternal {
			// Increase path if the current HOF is not xover and
			// this router is an ingress router.
			if _, err := reply.IncPath(); err != nil {
				return nil, err
			}
		}
	}
	if err := reply.replyEgress(rp.DirFrom, rp.Ingress.Src, rp.Ingress.IfID); err != nil {
		return nil, err
	}
	return reply, nil
}

// replyEgress calculates the corresponding egress function and destination
// address to use when replying to a packet.
func (rp *RtrPkt) replyEgress(dir rcmn.Dir, dst *overlay.OverlayAddr, ifid common.IFIDType) error {
	// Destination is the local AS
	if rp.dstIA.Equal(rp.Ctx.Conf.IA) {
		// Write to local socket
		rp.Egress = append(rp.Egress, EgressPair{S: rp.Ctx.LocSockOut, Dst: dst})
		return nil
	}
	// Destination AS is not local
	if dir == rcmn.DirExternal {
		rp.Egress = append(rp.Egress, EgressPair{S: rp.Ctx.ExtSockOut[ifid]})
		return nil
	}
	if assert.On {
		assert.Must(dir == rcmn.DirLocal, "Wrong direction value")
	}
	// DirFrom Local and destination is remote AS
	// At this point we should have a valid path to route the packet
	if _, err := rp.IFNext(); err != nil {
		return err
	}
	if err := rp.validateLocalIF(rp.ifNext); err != nil {
		return err
	}
	if _, ok := rp.Ctx.Conf.Net.IFs[*rp.ifNext]; ok {
		// Egress interface is on this BR
		// Re-inject to process the reply as an "Egress br"
		// and make it look like it arrived in the local socket
		rp.hooks.Route = append(rp.hooks.Route, rp.reprocess)
		return nil
	}
	// Egress interface is not on this BR
	// Write to local socket
	rp.Egress = append(rp.Egress, EgressPair{S: rp.Ctx.LocSockOut, Dst: dst})
	return nil
}
