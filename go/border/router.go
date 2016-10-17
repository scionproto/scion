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

package main

import (
	"sync"
	"time"

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
	Id        string
	inQs      []chan *rpkt.RtrPkt
	locOutFs  map[int]rpkt.OutputFunc
	intfOutFs map[spath.IntfID]rpkt.OutputFunc
	freePkts  chan *rpkt.RtrPkt
	revInfoQ  chan common.RawBytes
}

func NewRouter(id, confDir string) (*Router, *common.Error) {
	r := &Router{Id: id}
	if err := r.setup(confDir); err != nil {
		return nil, err
	}
	return r, nil
}

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
		metrics.PktProcessTime.Add(time.Now().Sub(rp.TimeIn).Seconds())
		r.recyclePkt(rp)
	}
}

func (r *Router) processPacket(rp *rpkt.RtrPkt) {
	defer liblog.PanicLog()
	if assert.On {
		assert.Must(len(rp.Raw) > 0, "Raw must not be empty")
		assert.Must(rp.DirFrom != rpkt.DirUnset, "DirFrom must be set")
		assert.Must(rp.TimeIn != time.Time{}, "TimeIn must be set")
		assert.Must(rp.Ingress.Src != nil, "Ingress.Src must be set")
		assert.Must(rp.Ingress.Dst != nil, "Ingress.Dst must be set")
		assert.Must(len(rp.Ingress.IfIDs) > 0, "Ingress.IfIDs must not be empty")
	}
	rp.Id = logext.RandId(4)
	rp.Logger = log.New("rpkt", rp.Id)
	if err := rp.Parse(); err != nil {
		r.handlePktError(rp, err, "Error parsing packet")
		return
	}
	if err := rp.Validate(); err != nil {
		r.handlePktError(rp, err, "Error validating packet")
		return
	}
	if err := rp.NeedsLocalProcessing(); err != nil {
		rp.Error("Error checking for local processing", err.Ctx...)
		return
	}
	if _, err := rp.Payload(true); err != nil {
		rp.Error("Error parsing payload", err.Ctx...)
		return
	}
	if err := rp.Process(); err != nil {
		r.handlePktError(rp, err, "Error processing packet")
		return
	}
	if rp.DirTo != rpkt.DirSelf {
		if err := rp.Route(); err != nil {
			r.handlePktError(rp, err, "Error routing packet")
		}
	}
}

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
