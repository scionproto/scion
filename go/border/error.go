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

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/inconshreveable/log15"
)

// handlePktError is called for protocol-level packet errors. If there's SCMP
// metadata attached to the error object, then an SCMP error response is
// generated and sent.
func (r *Router) handlePktError(rp *rpkt.RtrPkt, perr *common.Error, desc string) {
	sdata, ok := perr.Data.(*scmp.ErrData)
	if ok {
		perr.Ctx = append(perr.Ctx, "SCMP", sdata.CT)
	}
	rp.Error(desc, perr.Ctx...)
	if !ok || perr.Data == nil || rp.DirFrom == rpkt.DirSelf || rp.SCMPError {
		// No scmp error data, packet is from self, or packet is already an SCMPError, so no reply.
		return
	}
	if sdata.CT.Class == scmp.C_CmnHdr {
		switch sdata.CT.Type {
		case scmp.T_C_BadVersion, scmp.T_C_BadSrcType, scmp.T_C_BadDstType:
			// For any of these cases, do nothing. A reply would only be
			// possible in the case of a version/addr type being understood but
			// deprecated, which hasn't happened yet.
			return
		}
	}
	reply, err := r.createSCMPErrorReply(rp, sdata.CT, sdata.Info)
	if err != nil {
		rp.Error("Error creating SCMP response", err.Ctx...)
		return
	}
	reply.Route()
}

// createSCMPErrorReply generates an SCMP error reply to the supplied packet.
func (r *Router) createSCMPErrorReply(rp *rpkt.RtrPkt, ct scmp.ClassType,
	info scmp.Info) (*rpkt.RtrPkt, *common.Error) {
	// Create generic ScnPkt reply
	sp, err := r.createReplyScnPkt(rp)
	if err != nil {
		return nil, err
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
	sp.Pld = scmp.PldFromQuotes(ct, info, sp.L4.L4Type(), rp.GetRaw)
	sp.L4 = scmp.NewHdr(ct, sp.Pld.Len())
	// Convert back to RtrPkt
	reply, err := rpkt.RtrPktFromScnPkt(sp, rp.DirFrom)
	if err != nil {
		return nil, err
	}

	hopF, err := reply.HopF()
	if err != nil {
		return nil, err
	}
	if hopF.Xover {
		reply.InfoF()
		// Increase path if the segment was changed by this router.
		if rp.CmnHdr.CurrHopF == rp.CmnHdr.CurrInfoF + 8 {
			if err := reply.IncPath(); err != nil {
				return nil, err
			}
		}
		// Always increase path on a xover point.
		if err := reply.IncPath(); err != nil {
			return nil, err
		}
	} else if rp.DirFrom == rpkt.DirExternal {
		reply.InfoF()
		// Increase path if the packet is in the middle of a segment and
		// the current router is an ingress router.
		if err := reply.IncPath(); err != nil {
			return nil, err
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
func (r *Router) createReplyScnPkt(rp *rpkt.RtrPkt) (*spkt.ScnPkt, *common.Error) {
	sp, err := rp.ToScnPkt(false)
	if err != nil {
		return nil, err
	}
	if err = sp.Reverse(); err != nil {
		return nil, err
	}
	// Use the ingress address as the source host
	sp.SrcIA = conf.C.IA
	sp.SrcHost = addr.HostFromIP(rp.Ingress.Dst.IP)
	return sp, nil
}

// replyEgress calculates the corresponding egress function and destination
// address to use when replying to a packet.
func (r *Router) replyEgress(rp *rpkt.RtrPkt) (rpkt.EgressPair, *common.Error) {
	if rp.DirFrom == rpkt.DirLocal {
		locIdx := conf.C.Net.LocAddrMap[rp.Ingress.Dst.String()]
		return rpkt.EgressPair{F: r.locOutFs[locIdx], Dst: rp.Ingress.Src}, nil
	}
	intf, err := rp.IFCurr()
	if err != nil {
		return rpkt.EgressPair{}, err
	}
	return rpkt.EgressPair{F: r.intfOutFs[*intf], Dst: rp.Ingress.Src}, nil
}
