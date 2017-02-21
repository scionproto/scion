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

// This file contains the main router processing loop.

package main

import (
	"sync"

	"github.com/gavv/monotime"
	log "github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

type Router struct {
	// Id is the SCION element ID, e.g. "br4-21-9".
	Id string
	// inQs is a slice of channels that incoming packets are received from.
	// FIXME(kormat): maybe remove these in favour of just calling
	// processPacket directly.
	inQs []chan *rpkt.RtrPkt
	// locOutFs is a slice of functions for sending packets to local
	// destinations (i.e. within the local ISD-AS), indexed by the local
	// address id.
	locOutFs map[int]rpkt.OutputFunc
	// intfOutFs is a slice of functions for sending packets to neighbouring
	// ISD-ASes, indexed by the interface ID of the relevant link.
	intfOutFs map[spath.IntfID]rpkt.OutputFunc
	// freePkts is a buffered channel for recycled packets. See
	// Router.recyclePkt
	freePkts chan *rpkt.RtrPkt
	// revInfoQ is a channel for handling RevInfo payloads.
	revInfoQ chan rpkt.RevTokenCallbackArgs
}

func NewRouter(id, confDir string) (*Router, *common.Error) {
	r := &Router{Id: id}
	if err := r.setup(confDir); err != nil {
		return nil, err
	}
	return r, nil
}

// Run sets up networking, and starts go routines for handling the main packet
// processing as well as various other router functions.
func (r *Router) Run() *common.Error {
	if err := r.setupNet(); err != nil {
		return err
	}
	go r.SyncInterface()
	go r.IFStateUpdate()
	go r.RevInfoFwd()
	var wg sync.WaitGroup
	for _, q := range r.inQs {
		wg.Add(1)
		go r.handleQueue(q)
	}
	wg.Wait()
	return nil
}

func (r *Router) handleQueue(q chan *rpkt.RtrPkt) {
	defer liblog.PanicLog()
	for rp := range q {
		r.processPacket(rp)
		metrics.PktProcessTime.Add(monotime.Since(rp.TimeIn).Seconds())
		r.recyclePkt(rp)
	}
}

// processPacket is the heart of the router's packet handling. It delegates
// everything from parsing the incoming packet, to routing the outgoing packet.
func (r *Router) processPacket(rp *rpkt.RtrPkt) {
	defer liblog.PanicLog()
	if assert.On {
		assert.Must(len(rp.Raw) > 0, "Raw must not be empty")
		assert.Must(rp.DirFrom != rpkt.DirUnset, "DirFrom must be set")
		assert.Must(rp.TimeIn != 0, "TimeIn must be set")
		assert.Must(rp.Ingress.Src != nil, "Ingress.Src must be set")
		assert.Must(rp.Ingress.Dst != nil, "Ingress.Dst must be set")
		assert.Must(len(rp.Ingress.IfIDs) > 0, "Ingress.IfIDs must not be empty")
	}
	// Assign a pseudorandom ID to the packet, for correlating log entries.
	rp.Id = logext.RandId(4)
	rp.Logger = log.New("rpkt", rp.Id)
	if err := rp.Parse(); err != nil {
		r.handlePktError(rp, err, "Error parsing packet")
		return
	}
	// Validation looks for errors in the packet that didn't break basic
	// parsing.
	if err := rp.Validate(); err != nil {
		r.handlePktError(rp, err, "Error validating packet")
		return
	}
	// Check if the packet needs to be processed locally, and if so register
	// hooks for doing so.
	if err := rp.NeedsLocalProcessing(); err != nil {
		rp.Error("Error checking for local processing", err.Ctx...)
		return
	}
	// Parse the packet payload, if a previous step has registered a relevant
	// hook for doing so.
	if _, err := rp.Payload(true); err != nil {
		// Any errors at this point are application-level, and hence not
		// calling handlePktError, as no SCMP errors will be sent.
		rp.Error("Error parsing payload", err.Ctx...)
		return
	}
	// Process the packet, if a previous step has registered a relevant hook
	// for doing so.
	if err := rp.Process(); err != nil {
		r.handlePktError(rp, err, "Error processing packet")
		return
	}
	// If the packet's destination is this router, there's no need to forward
	// it.
	if rp.DirTo != rpkt.DirSelf {
		if err := rp.Route(); err != nil {
			r.handlePktError(rp, err, "Error routing packet")
		}
	}
}

// getPktBuf implements a leaky buffer list, as described
// here: https://golang.org/doc/effective_go.html#leaky_buffer
func (r *Router) getPktBuf() *rpkt.RtrPkt {
	select {
	case rp := <-r.freePkts:
		// Got one
		metrics.PktBufReuse.Inc()
		return rp
	default:
		// None available, allocate a new one
		metrics.PktBufNew.Inc()
		return rpkt.NewRtrPkt()
	}
}

// recyclePkt readies a packet for the leaky buffer list (see getPktBuf).
func (r *Router) recyclePkt(rp *rpkt.RtrPkt) {
	rp.Reset()
	select {
	case r.freePkts <- rp:
		// Packet added to free list
	default:
		// Free list full, carry on
		metrics.PktBufDiscard.Inc()
	}
}
