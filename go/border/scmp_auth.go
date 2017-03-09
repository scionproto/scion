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

// This file handles SCMPAuth key management.
// This includes SCMPAuth DRKey exchange as well as the packet buffering.

package main

import (
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/proto"
	"time"
)

//////////////////////////////////
// Callbacks used by rpkt
//////////////////////////////////

// PutSCMPAuthDRKeyRequest is a callback called to enqueue missing SCMPAuthDRKeys.
// A request is forwarded to RequestSCMPAuthDRKeys if no request of the same type has already been made
// and the request Queue is not full yet.

func (r *Router) PutSCMPAuthDRKeyRequest(isdAs *addr.ISD_AS, origRp *rpkt.RtrPkt) rpkt.SCMPAuthPutResult {
	iA := isdAs.Uint32()
	r.missingSCMPAuthDRKeys.Lock()
	elem, present := r.missingSCMPAuthDRKeys.GetFreeIfNotPresent(iA)
	switch {
	case !present && elem != nil:
		origRp.Debug("RequestSCMPAuthDRKeys: Request added", "ISD-AS", isdAs.String())
		timeStamp := time.Now().UnixNano()
		elem.InsertionTime = timeStamp
		elem.IsdAs = iA
		r.missingSCMPAuthDRKeys.Append(elem)
	case !present && elem == nil:
		origRp.Debug("RequestSCMPAuthDRKeys: Request not added. Request buffer full.", "ISD-AS", isdAs.String())
		return rpkt.SCMPAuthDRKeyQueueFull
	default:
		origRp.Debug("RequestSCMPAuthDRKeys: Request not added. Request already present.")
	}
	r.missingSCMPAuthDRKeys.Unlock()

	if !present {
		select {
		case r.missingSCMPAuthDRKeys.Channel <- iA:
		default:
			origRp.Warn("RequestSCMPAuthDRKeys: Dropping request. Channel is blocking.", "ISD-AS", isdAs.String())
			r.missingSCMPAuthDRKeys.Lock()
			elem := r.missingSCMPAuthDRKeys.Remove(elem.IsdAs)
			r.missingSCMPAuthDRKeys.RecycleFree(elem)
			r.missingSCMPAuthDRKeys.Unlock()
			return rpkt.SCMPAuthChannelBlocking
		}

	}

	if ok := r.scmpAuthAddQueueIfNotPresent(iA); !ok {
		origRp.Debug("RequestSCMPAuthDRKeys: Dropping pkt. No Queue available.")
		return rpkt.SCMPAuthNoPktQueueAvailable
	}

	r.scmpAuthQueues.RLock()
	defer r.scmpAuthQueues.RUnlock()

	if queue, ok := r.scmpAuthQueues.Map[isdAs.Uint32()]; ok {
		if r.scmpAuthAddPacketToQueue(queue, origRp) {
			return rpkt.SCMPAuthSuccess
		} else {
			return rpkt.SCMPAuthPktQueueFull
		}
	} else {
		origRp.Debug("RequestSCMPAuthDRKeys: Dropping pkt. Queue was freed.")
		return rpkt.SCMPAuthPktQueueFreed
	}
}

// ProcessSCMPAuthLocalDRKeyReply processes SCMP Auth replies from the local CS to the BR called by rpkt.
// A request is forwarded to the go routine HandleSCMPAuthDRKeyReplies which handles further processing.
func (r *Router) ProcessSCMPAuthLocalDRKeyReply(rep proto.ScmpAuthLocalRep) {

	isdAs := rep.Isdas()
	// TODO(roosd): encrypt local communication between CS and BR
	cipher, serr := rep.Cipher()
	if serr != nil {
		log.Error("Unable to extract cipher from SCMPAuthLocalDRKeyReply", "err", serr)
		return
	}

	drkey := make(common.RawBytes, 16)
	log.Debug("ProcessSCMPAuthLocalDRKeyReply: Received DRKey.", "ISD-AS", addr.IAFromUint32(isdAs).String(), "Cipher", cipher)
	copy(drkey, cipher)
	log.Debug("ProcessSCMPAuthLocalDRKeyReply: Received DRKey.", "ISD-AS", addr.IAFromUint32(isdAs).String(), "DRKey", drkey, "Cipher", cipher)

	select {
	case r.scmpAuthDRKeys.Channel <- rpkt.SCMPAuthDRKeyReplyElement{IsdAs: isdAs, DRKey: drkey}:
	default:
		log.Debug("Dropping SCMPAuthDRKeyReply. Channel is blocking.", "ISD-AS", addr.IAFromUint32(isdAs).String())
	}
}

//////////////////////////////////
// Go routines run by router
//////////////////////////////////

// RequestSCMPAuthDRKeys is a go routine dedicated to create and send SCMPAuthDRKey requests to the local CS.
func (r *Router) RequestSCMPAuthDRKeys() {
	defer liblog.PanicLog()
	// Run forever.
	for isdAs := range r.missingSCMPAuthDRKeys.Channel {
		r.genSCMPAuthLocalDRKeyReq(isdAs)
	}

}

// ExpireSCMPAuthDRKeyRequests is a go routine dedicated to expire SCMPAuthDRKey requests in the request queue.
// Note: The queue is ordered by insertion time, thus also by expiration time.
func (r *Router) ExpireSCMPAuthDRKeyRequests() {
	defer liblog.PanicLog()
	// Run forever.
	for {
		var elem *rpkt.MissingSCMPAuthDRKeyElement

		r.missingSCMPAuthDRKeys.RLock()
		if elem = r.missingSCMPAuthDRKeys.Peak(); elem == nil {
			r.missingSCMPAuthDRKeys.RUnlock()
			// A request entering just now will expire in about DRKeyRequestTimeout.
			time.Sleep(time.Nanosecond * time.Duration(conf.SCMPAuth.DRKeyRequestTimeout))
			continue
		}
		delta := conf.SCMPAuth.DRKeyRequestTimeout - (time.Now().UnixNano() - elem.InsertionTime)
		r.missingSCMPAuthDRKeys.RUnlock()

		// Queue is sorted by insertion time. Thus, if delta > 0 -> no element is expired yet.
		// Nothing to do until delta has passed.
		if delta > 0 {
			elem = nil
			time.Sleep(time.Nanosecond * time.Duration(delta))
			continue
		}

		r.missingSCMPAuthDRKeys.Lock()
		if elem = r.missingSCMPAuthDRKeys.Peak(); elem != nil {
			delta = conf.SCMPAuth.DRKeyRequestTimeout - (time.Now().UnixNano() - elem.InsertionTime)

			// make sure, the head is still an expired element.
			if delta <= 0 {
				elem = r.missingSCMPAuthDRKeys.Pop()
				log.Debug("ExpireSCMPAuthDRKeyRequests: expired request.", "ISD-AS", addr.IAFromUint32(elem.IsdAs).String())
				r.scmpAuthDropExpiredPkts(elem.IsdAs)
				r.missingSCMPAuthDRKeys.RecycleFree(elem)
			}
		}
		r.missingSCMPAuthDRKeys.Unlock()
	}
}

// HandleSCMPAuthDRKeyReplies is a go routine dedicated to clearing out the SCMP packet buffer.
func (r *Router) HandleSCMPAuthDRKeyReplies() {
	defer liblog.PanicLog()
	// Run forever.
	for rep := range r.scmpAuthDRKeys.Channel {

		r.scmpAuthDRKeys.Lock()
		r.scmpAuthDRKeys.Map[rep.IsdAs] = rep.DRKey
		r.scmpAuthDRKeys.Unlock()

		r.missingSCMPAuthDRKeys.Lock()
		elem := r.missingSCMPAuthDRKeys.Remove(rep.IsdAs)
		r.missingSCMPAuthDRKeys.RecycleFree(elem)
		r.missingSCMPAuthDRKeys.Unlock()

		r.scmpAuthDeliverPkts(rep.IsdAs)
	}

}

//////////////////////////////////
// Helper routines
//////////////////////////////////

// scmpAuthAddQueueIfNotPresent adds a queue for the given ISD-AS into the packet buffer data structure.
// It returns the state of presence of a packet buffer for given ISD-AS after returning.
func (r *Router) scmpAuthAddQueueIfNotPresent(isdAs uint32) bool {
	r.scmpAuthQueues.Lock()
	if _, present := r.scmpAuthQueues.Map[isdAs]; !present {
		if ok := r.scmpAuthQueues.AddQueue(isdAs); !ok {
			r.scmpAuthQueues.Unlock()
			return false
		}
	}
	r.scmpAuthQueues.Unlock()
	return true
}

// scmpAuthAddPacketToQueue adds a SCMP packet to the packet buffer if there is space.
// It returns if the packet was added.
func (r *Router) scmpAuthAddPacketToQueue(queue *rpkt.SCMPAuthQueue, origRp *rpkt.RtrPkt) bool {
	queue.Lock()
	defer queue.Unlock()
	switch {
	case queue.Free:
		origRp.Debug("RequestSCMPAuthDRKeys: Dropping pkt. Queue already Free.")
	case len(queue.Rpkts) < cap(queue.Rpkts):
		origRp.Debug("RequestSCMPAuthDRKeys: Added pkt.")
		rp := r.getPktBuf()
		rp.DirFrom = origRp.DirFrom
		rp.Raw = rp.Raw[:len(origRp.Raw)]
		copy(rp.Raw, origRp.Raw)
		rp.TimeIn = origRp.TimeIn
		rp.Ingress.Src = origRp.Ingress.Src
		rp.Ingress.Dst = origRp.Ingress.Dst
		rp.Ingress.IfIDs = origRp.Ingress.IfIDs
		queue.Rpkts = append(queue.Rpkts, rp)
		return true
	default:
		origRp.Debug("RequestSCMPAuthDRKeys: Dropping pkt. Queue Full.")
	}
	return false
}

// scmpAuthDropExpiredPkts drops the expired packets of a given ISD-AS and recylces the packet buffer.
func (r *Router) scmpAuthDropExpiredPkts(isdAs uint32) {
	r.scmpAuthQueues.Lock()
	if queue := r.scmpAuthQueues.PopQueue(isdAs); queue != nil {
		r.scmpAuthQueues.Unlock()

		for i := 0; i < len(queue.Rpkts); i++ {
			r.recyclePkt(queue.Rpkts[i])
		}
		r.scmpAuthQueues.Lock()
		r.scmpAuthQueues.RecycleQueue(queue)
		r.scmpAuthQueues.Unlock()
	} else {
		r.scmpAuthQueues.Unlock()
		log.Debug("ExpireSCMPAuthDRKeyRequests: No Queue to recycle.")
	}
}

// scmpAuthDeliverPkts delivers the buffered packets to the routing routine to be processed again.
// Also, the packet buffer is recycled.
func (r *Router) scmpAuthDeliverPkts(isdAs uint32) {
	r.scmpAuthQueues.Lock()
	if queue := r.scmpAuthQueues.PopQueue(isdAs); queue != nil {
		r.scmpAuthQueues.Unlock()

		for i := 0; i < len(queue.Rpkts); i++ {
			r.scmpAuthQueues.RtrPktChannel <- queue.Rpkts[i]
		}

		r.scmpAuthQueues.Lock()
		r.scmpAuthQueues.RecycleQueue(queue)
		r.scmpAuthQueues.Unlock()
	} else {
		r.scmpAuthQueues.Unlock()
		log.Debug("ExpireSCMPAuthDRKeyRequests: No Queue to recycle.")
	}
}

// genSCMPAuthLocalDRKeyReq generates a SCMPAuth Drkey requests and sends it to the local CS.
func (r *Router) genSCMPAuthLocalDRKeyReq(isdAS uint32) {
	log.Debug("GenSCMPAuthLocalDRKeyReq: Handle request", "ISD-AS", addr.IAFromUint32(isdAS).String())
	// Pick first local address from topology as source.
	srcAddr := conf.C.Net.LocAddr[0].PublicAddr()
	dstHost := addr.SvcCS.Multicast()
	// Create base packet
	rp, err := rpkt.RtrPktFromScnPkt(&spkt.ScnPkt{
		SrcIA: conf.C.IA, SrcHost: addr.HostFromIP(srcAddr.IP),
		DstIA: conf.C.IA, DstHost: dstHost,
		L4: &l4.UDP{SrcPort: uint16(srcAddr.Port), DstPort: 0},
	}, rpkt.DirLocal)
	if err != nil {
		log.Error("Error creating SCMPAuthLocalDRKeyRequest packet", err.Ctx...)
		return
	}
	// Create payload
	scion, scmpAuthMgmt, err := proto.NewSCMPAuthMgmtMsg()
	if err != nil {
		log.Error("Error creating scmpAuthMgmt payload", err.Ctx...)
		return
	}

	scmpAuthLocalReq, cerr := scmpAuthMgmt.NewScmpAuthLocalReq()
	if cerr != nil {
		log.Error("Unable to create SCMPAuthLocalDRKeyReq struct", "err", cerr)
		return
	}
	scmpAuthLocalReq.SetIsdas(isdAS)

	rp.SetPld(&spkt.SCMPAuthMgmtPld{SCION: scion})
	_, err = rp.RouteResolveSVCMulti(dstHost, r.locOutFs[0])
	if err != nil {
		log.Error("Unable to route SCMPAuthLocalDRKeyRequest packet", err.Ctx...)
	}
	rp.Route()
}
