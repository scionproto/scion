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
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/packet"
	"github.com/netsec-ethz/scion/go/lib/log"
)

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
