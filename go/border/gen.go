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

// This file provides a generic interface to periodically generate SCION packets
// and send them out.

package main

import (
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/spkt"
)

// genPkt is a generic function to generate packets that originate at the router.
func (r *Router) genPkt(dstIA addr.IA, dst, src *addr.AppAddr, oAddr *overlay.OverlayAddr,
	pld common.Payload) error {

	if dst == nil {
		return common.NewBasicError("genPkt: Missing dst", nil)
	}
	if src == nil {
		return common.NewBasicError("genPkt: Missing src", nil)
	}
	ctx := rctx.Get()
	// Create base packet
	sp := &spkt.ScnPkt{
		DstIA: dstIA, SrcIA: ctx.Conf.IA, DstHost: dst.L3, SrcHost: src.L3,
	}
	if src.L4 != nil && dst.L4 != nil {
		sp.L4 = &l4.UDP{SrcPort: src.L4.Port(), DstPort: dst.L4.Port()}
	}
	rp, err := rpkt.RtrPktFromScnPkt(sp, ctx)
	if err != nil {
		return err
	}
	if err = rp.SetPld(pld); err != nil {
		return err
	}
	if dstIA.Eq(ctx.Conf.IA) {
		// Packet is destined to local AS
		if dst.L3.Type() == addr.HostTypeSVC {
			if _, err := rp.RouteResolveSVC(); err != nil {
				return err
			}
		} else {
			rp.Egress = append(rp.Egress, rpkt.EgressPair{S: ctx.LocSockOut, Dst: oAddr})
		}
	} else {
		ifid, ok := ctx.Conf.Net.IFAddrMap[src.String()]
		if !ok {
			return common.NewBasicError("genPkt: unable to find ifid for address",
				nil, "addr", src)
		}
		rp.Egress = append(rp.Egress, rpkt.EgressPair{S: ctx.ExtSockOut[ifid]})
	}
	return rp.Route()
}
