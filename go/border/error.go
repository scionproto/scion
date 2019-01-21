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

// This file contains the router-level handling of packet errors. When
// possible/allowed, a relevant SCMP error message reply is sent to the sender.

package main

import (
	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scmp"
)

type pktErrorArgs struct {
	rp   *rpkt.RtrPkt
	perr error
}

// handlePktError is called to enqueue packets with protocol-level errors
// for handling by the PacketError goroutine.
func (r *Router) handlePktError(rp *rpkt.RtrPkt, perr error, desc string) {
	// XXX(kormat): uncomment for debugging:
	// perr = common.NewBasicError("Raw packet", perr, "raw", rp.Raw)
	rp.Error(desc, "err", perr)
	rp.RefInc(1)
	args := pktErrorArgs{rp: rp, perr: perr}
	select {
	case r.pktErrorQ <- args:
	default:
		log.Debug("Dropping pkt error")
		rp.Release()
	}
}

// PackeError creates an SCMP error for the given packet and sends it to its source.
func (r *Router) PacketError() {
	// Run forever.
	for args := range r.pktErrorQ {
		r.doPktError(args.rp, args.perr)
		args.rp.Release()
	}
}

// doPktError is called for protocol-level packet errors. If there's SCMP
// metadata attached to the error object, then an SCMP error response is
// generated and sent.
func (r *Router) doPktError(rp *rpkt.RtrPkt, perr error) {
	serr := scmp.ToError(perr)
	if serr == nil || rp.DirFrom == rcmn.DirSelf || rp.SCMPError {
		// No scmp error data, packet is from self, or packet is already an SCMPError, so no reply.
		return
	}
	switch serr.CT.Class {
	case scmp.C_CmnHdr:
		switch serr.CT.Type {
		case scmp.T_C_BadVersion, scmp.T_C_BadDstType, scmp.T_C_BadSrcType:
			// For any of these cases, do nothing. A reply would only be
			// possible in the case of a version/addr type being understood but
			// deprecated, which hasn't happened yet.
			return
		}
	}
	srcIA, err := rp.SrcIA()
	if err != nil {
		return
	}
	// Certain errors are not respondable to if the source lies in a remote AS.
	if !srcIA.Equal(rp.Ctx.Conf.IA) {
		switch serr.CT.Class {
		case scmp.C_CmnHdr:
			switch serr.CT.Type {
			case scmp.T_C_BadHopFOffset, scmp.T_C_BadInfoFOffset:
				return
			}
		case scmp.C_Path:
			switch serr.CT.Type {
			case scmp.T_P_PathRequired:
				return
			}
		}
	}
	reply, err := r.createSCMPErrorReply(rp, serr.CT, serr.Info)
	if err != nil {
		rp.Error("Error creating SCMP response", "err", err)
		return
	}
	reply.Route()
}

// createSCMPErrorReply generates an SCMP error reply to the supplied packet.
func (r *Router) createSCMPErrorReply(rp *rpkt.RtrPkt, ct scmp.ClassType,
	info scmp.Info) (*rpkt.RtrPkt, error) {
	// Create generic ScnPkt reply
	sp, err := rp.CreateReplyScnPkt()
	if err != nil {
		return nil, err
	}
	if ct.Class == scmp.C_CmnHdr &&
		(ct.Type == scmp.T_C_BadInfoFOffset || ct.Type == scmp.T_C_BadHopFOffset) {
		// If the infoF or hopF offsets are bad, then don't include the path
		// header in the response. This is only relevant for packets sent from the local AS,
		// packets from external ASes are already filtered out in handlePktError() above.
		sp.Path = nil
	}
	oldHBH := sp.HBHExt
	sp.HBHExt = make([]common.Extension, 0, common.ExtnMaxHBH+1)
	// Add new SCMP HBH extension at the start.
	ext := &scmp.Extn{Error: true}
	if ct.Class == scmp.C_Path && ct.Type == scmp.T_P_RevokedIF {
		// Revocation SCMP errors have to be inspected by intermediate routers.
		ext.HopByHop = true
	}
	sp.HBHExt = append(sp.HBHExt, ext)
	// Filter out any existing SCMP HBH headers, and trim the list to
	// common.ExtnMaxHBH.
	for _, e := range oldHBH {
		if len(sp.HBHExt) < cap(sp.HBHExt) && e.Type() != common.ExtnSCMPType {
			sp.HBHExt = append(sp.HBHExt, e)
		}
	}
	sp.Pld = scmp.PldFromQuotes(ct, info, rp.L4Type, rp.GetRaw)
	sp.L4 = scmp.NewHdr(ct, sp.Pld.Len())
	return rp.CreateReply(sp)
}
