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
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type Router struct {
	Id        string
	inQs      []chan *rpkt.RPkt
	locOutFs  map[int]rpkt.OutputFunc
	intfOutFs map[spath.IntfID]rpkt.OutputFunc
	freePkts  chan *rpkt.RPkt
	revInfoQ  chan util.RawBytes
}

// FIXME(kormat): this should be reduced as soon as we respect the actual link
// MTU.
const pktBufSize = 1 << 16

func NewRouter(id, confDir string) (*Router, *util.Error) {
	r := &Router{Id: id}
	if err := r.setup(confDir); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Router) Run() *util.Error {
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

func (r *Router) handleQueue(q chan *rpkt.RPkt) {
	defer liblog.PanicLog()
	for rp := range q {
		r.processPacket(rp)
		metrics.PktProcessTime.Add(time.Now().Sub(rp.TimeIn).Seconds())
		r.recyclePkt(rp)
	}
}

func (r *Router) processPacket(rp *rpkt.RPkt) {
	rp.Logger = log.New("rpkt", logext.RandId(4))
	if err := rp.Parse(); err != nil {
		rp.Error("Error during parsing", err.Ctx...)
		return
	}
	if err := rp.Validate(); err != nil {
		rp.Error("Error validating packet", err.Ctx...)
		return
	}
	if err := rp.NeedsLocalProcessing(); err != nil {
		rp.Error("Error checking for local processing", err.Ctx...)
		return
	}
	if _, err := rp.Payload(); err != nil {
		rp.Error("Error parsing payload", err.Ctx...)
		return
	}
	if err := rp.Process(); err != nil {
		rp.Error("Error processing packet", err.Ctx...)
		return
	}
	if err := rp.Route(); err != nil {
		rp.Error("Error routing packet", err.Ctx...)
	}
}

func (r *Router) recyclePkt(rp *rpkt.RPkt) {
	if rp.DirFrom == rpkt.DirSelf {
		return
	}
	if cap(rp.Raw) != pktBufSize {
		rp.Crit("Raw", "len", len(rp.Raw), "cap", cap(rp.Raw))
		return
	}
	rp.Reset()
	select {
	case r.freePkts <- rp:
		// Packet added to free list
	default:
		// Free list full, carry on
		metrics.PktBufDiscard.Inc()
	}
}
