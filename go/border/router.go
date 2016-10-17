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
	"github.com/netsec-ethz/scion/go/border/packet"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type Router struct {
	Id        string
	inQs      []chan *packet.Packet
	locOutFs  map[int]packet.OutputFunc
	intfOutFs map[spath.IntfID]packet.OutputFunc
	freePkts  chan *packet.Packet
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

func (r *Router) handleQueue(q chan *packet.Packet) {
	defer liblog.PanicLog()
	for p := range q {
		r.processPacket(p)
		metrics.PktProcessTime.Add(time.Now().Sub(p.TimeIn).Seconds())
		r.recyclePkt(p)
	}
}

func (r *Router) processPacket(p *packet.Packet) {
	p.Logger = log.New("pkt", logext.RandId(4))
	if err := p.Parse(); err != nil {
		p.Error("Error during parsing", err.Ctx...)
		return
	}
	if err := p.Validate(); err != nil {
		p.Error("Error validating packet", err.Ctx...)
		return
	}
	if err := p.NeedsLocalProcessing(); err != nil {
		p.Error("Error checking for local processing", err.Ctx...)
		return
	}
	if _, err := p.Payload(); err != nil {
		p.Error("Error parsing payload", err.Ctx...)
		return
	}
	if err := p.Process(); err != nil {
		p.Error("Error processing packet", err.Ctx...)
		return
	}
	if err := p.Route(); err != nil {
		p.Error("Error routing packet", err.Ctx...)
	}
}

func (r *Router) recyclePkt(p *packet.Packet) {
	if p.DirFrom == packet.DirSelf {
		return
	}
	if cap(p.Raw) != pktBufSize {
		p.Crit("Raw", "len", len(p.Raw), "cap", cap(p.Raw))
		return
	}
	p.Reset()
	select {
	case r.freePkts <- p:
		// Packet added to free list
	default:
		// Free list full, carry on
		metrics.PktBufDiscard.Inc()
	}
}
