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

// This file contains the router-level handling of packet errors. When
// possible/allowed, a relevant SCMP error message reply is sent to the sender.

package main

import (
	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/rcmn"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spkt"
)

// handlePktError is called for protocol-level packet errors. If there's SCMP
// metadata attached to the error object, then an SCMP error response is
// generated and sent.
func (r *Router) handlePktError(rp *rpkt.RtrPkt, perr error, desc string) {
	pcerr := perr.(*common.CError)
	sdata, ok := pcerr.Data.(*scmp.ErrData)
	if ok {
		pcerr.AddCtx("SCMP", sdata.CT)
	}
	// XXX(kormat): uncomment for debugging:
	// pcerr.AddCtx("raw", rp.Raw)
	rp.Error(desc, "err", pcerr)
	if !ok || pcerr.Data == nil || rp.DirFrom == rcmn.DirSelf || rp.SCMPError {
		// No scmp error data, packet is from self, or packet is already an SCMPError, so no reply.
		return
	}
	switch sdata.CT.Class {
	case scmp.C_CmnHdr:
		switch sdata.CT.Type {
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
	if !srcIA.Eq(rp.Ctx.Conf.IA) {
		switch sdata.CT.Class {
		case scmp.C_CmnHdr:
			switch sdata.CT.Type {
			case scmp.T_C_BadHopFOffset, scmp.T_C_BadInfoFOffset:
				return
			}
		case scmp.C_Path:
			switch sdata.CT.Type {
			case scmp.T_P_PathRequired:
				return
			}
		}

	}
	reply, err := r.createSCMPErrorReply(rp, sdata.CT, sdata.Info)
	if err != nil {
		cerr := err.(*common.CError)
		rp.Error("Error creating SCMP response", cerr.Ctx...)
		return
	}
	reply.Route()
}

// createSCMPErrorReply generates an SCMP error reply to the supplied packet.
func (r *Router) createSCMPErrorReply(rp *rpkt.RtrPkt, ct scmp.ClassType,
	info scmp.Info) (*rpkt.RtrPkt, error) {
	// Create generic ScnPkt reply
	sp, err := r.createReplyScnPkt(rp)
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
	// Add SCMP l4 header and payload
	var l4Type common.L4ProtocolType
	if sp.L4 != nil {
		l4Type = sp.L4.L4Type()
	}
	sp.Pld = scmp.PldFromQuotes(ct, info, l4Type, rp.GetRaw)
	sp.L4 = scmp.NewHdr(ct, sp.Pld.Len())
	// Convert back to RtrPkt
	reply, err := rpkt.RtrPktFromScnPkt(sp, rp.DirFrom, rp.Ctx)
	if err != nil {
		return nil, err
	}
	dstIA, err := reply.DstIA()
	if err != nil {
		return nil, err
	}
	// Only (potentially) call IncPath if the dest is not in the local AS.
	if !dstIA.Eq(rp.Ctx.Conf.IA) {
		hopF, err := reply.HopF()
		if err != nil {
			return nil, err
		}
		if hopF != nil && hopF.Xover {
			reply.InfoF()
			reply.UpFlag()
			// Always increment reversed path on a xover point.
			if _, err := reply.IncPath(); err != nil {
				return nil, err
			}
			// Increment reversed path if it was incremented in the forward direction.
			// Check
			// https://github.com/netsec-ethz/scion/blob/master/doc/PathReversal.md
			// for details.
			if rp.IncrementedPath {
				if _, err := reply.IncPath(); err != nil {
					return nil, err
				}
			}
		} else if rp.DirFrom == rcmn.DirExternal {
			reply.InfoF()
			reply.UpFlag()
			// Increase path if the current HOF is not xover and
			// this router is an ingress router.
			if _, err := reply.IncPath(); err != nil {
				return nil, err
			}
		}
	}
	egress, err := r.replyEgress(rp)
	if err != nil {
		return nil, err
	}
	reply.Egress = append(reply.Egress, egress)
	return reply, nil
}

// createReplyScnPkt creates a generic ScnPkt reply, by converting the RtrPkt
// to an ScnPkt, then reversing the ScnPkt, and setting the reply source address.
func (r *Router) createReplyScnPkt(rp *rpkt.RtrPkt) (*spkt.ScnPkt, error) {
	sp, err := rp.ToScnPkt(false)
	if err != nil {
		return nil, err
	}
	if err = sp.Reverse(); err != nil {
		return nil, err
	}
	// Use the ingress address as the source host
	sp.SrcIA = rp.Ctx.Conf.IA
	sp.SrcHost = addr.HostFromIP(rp.Ingress.Dst.IP)
	return sp, nil
}

// replyEgress calculates the corresponding egress function and destination
// address to use when replying to a packet.
func (r *Router) replyEgress(rp *rpkt.RtrPkt) (rpkt.EgressPair, error) {
	if rp.DirFrom == rcmn.DirLocal {
		return rpkt.EgressPair{S: rp.Ctx.LocSockOut[rp.Ingress.LocIdx], Dst: rp.Ingress.Src}, nil
	}
	ifid, err := rp.IFCurr()
	if err != nil {
		return rpkt.EgressPair{}, err
	}
	intf := rp.Ctx.Conf.Net.IFs[*ifid]
	return rpkt.EgressPair{S: rp.Ctx.ExtSockOut[*ifid], Dst: intf.RemoteAddr}, nil
}
