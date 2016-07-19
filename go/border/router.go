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
	"crypto/cipher"
	"net"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/netconf"
	"github.com/netsec-ethz/scion/go/border/packet"
	"github.com/netsec-ethz/scion/go/border/path"
	"github.com/netsec-ethz/scion/go/lib/as_conf"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/topology"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type Router struct {
	Id         string
	Topo       *topology.TopoBR
	ASConf     *as_conf.ASConf
	HFGenBlock cipher.Block
	NetConf    *netconf.NetConf
	inQs       []chan *packet.Packet
	locOutQs   map[int]packet.OutputFunc
	intfOutQs  map[path.IntfID]packet.OutputFunc
	freePkts   chan *packet.Packet
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
	if err := r.startup(); err != nil {
		return err
	}
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
		metrics.PktsRecv.Inc()
		metrics.BytesRecv.Add(float64(len(p.Raw)))
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
	if err := p.Process(); err != nil {
		p.Error("Error processing packet", err.Ctx...)
	}
	if err := p.Route(); err != nil {
		p.Error("Error routing packet", err.Ctx...)
	}
}

func (r *Router) readInput(in *net.UDPConn, dirFrom packet.Dir, q chan *packet.Packet) {
	defer liblog.PanicLog()
	log.Info("Listening", "addr", in.LocalAddr())
	dst := in.LocalAddr().(*net.UDPAddr)
	for {
		// https://golang.org/doc/effective_go.html#leaky_buffer
		var p *packet.Packet
		select {
		case p = <-r.freePkts:
			// Got one
			metrics.PktBufReuse.Inc()
		default:
			// None available, allocate a new one
			metrics.PktBufNew.Inc()
			p = new(packet.Packet)
			p.Raw = make([]byte, pktBufSize)
		}
		p.DirFrom = dirFrom
		length, src, err := in.ReadFromUDP(p.Raw)
		if err != nil {
			log.Error("Error reading from socket", "socket", dst, "err", err)
			continue
		}
		p.TimeIn = time.Now()
		p.Raw = p.Raw[:length] // Set the length of the slice
		p.Ingress.Src = src
		p.Ingress.Dst = dst
		q <- p
	}
}

func (r *Router) writeLocalOutput(out *net.UDPConn, p *packet.Packet) {
	if len(p.Egress) == 0 {
		p.Error("Destination not specified")
		return
	}
	for _, epair := range p.Egress {
		if count, err := out.WriteToUDP(p.Raw, epair.Dst); err != nil {
			p.Error("Error sending packet", "err", err)
			return
		} else if count != len(p.Raw) {
			p.Error("Unable to write full packet", "len", count)
			return
		}
		metrics.BytesSent.Add(float64(len(p.Raw)))
		metrics.PktsSent.Inc()
	}
}

func (r *Router) writeIntfOutput(out *net.UDPConn, p *packet.Packet) {
	if len(p.Egress) == 0 {
		p.Error("Destination not specified")
		return
	}
	if count, err := out.Write(p.Raw); err != nil {
		p.Error("Error sending packet", "err", err)
		return
	} else if count != len(p.Raw) {
		p.Error("Unable to write full packet", "len", count)
		return
	}
	metrics.BytesSent.Add(float64(len(p.Raw)))
	metrics.PktsSent.Inc()
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
