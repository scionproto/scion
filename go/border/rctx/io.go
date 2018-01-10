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
package rctx

import (
	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay/conn"
	"github.com/scionproto/scion/go/lib/ringbuf"
)

// SockFunc is a function that is started as a goroutine by
// Sock.Start()/Sock.Stop() to read/write to the underlying connection.
type SockFunc func(sock *Sock, stop, stopped chan struct{})

// Sock represents one direction of data-flow from an underlying connection.
// Each connection will have 2 Sock's associated, one for reading data from the
// network, the other for writing data to the network.
type Sock struct {
	// Ring is a ring-buffer that's written to by writers, and read from by readers.
	Ring *ringbuf.Ring
	// Conn is the underlying connection that this Sock represents.
	Conn conn.Conn
	// Dir is the direction that a packet is being read from/written to.
	Dir rcmn.Dir
	// Ifids is the list of interface IDs associated with a connection.
	Ifids []common.IFIDType
	// LocIdx is the local address index. It is only meaningful for packets
	// received from the local AS.
	LocIdx int
	// Labels holds the exported prometheus labels.
	Labels prometheus.Labels
	// Reader is an optional function that reads from Sock.Ring. It is spawned
	// in a go routine when Sock.Start() is called.
	Reader SockFunc
	// Writer is an optional function that writes to Sock.Ring. It is spawned
	// in a go routine when Sock.Start() is called.
	Writer        SockFunc
	stop          chan struct{}
	readerStopped chan struct{}
	writerStopped chan struct{}
	running       bool
}

func NewSock(ring *ringbuf.Ring, conn conn.Conn, dir rcmn.Dir,
	ifids []common.IFIDType, locIdx int, labels prometheus.Labels, reader, writer SockFunc) *Sock {
	s := &Sock{
		Ring: ring, Conn: conn, Dir: dir, Ifids: ifids, LocIdx: locIdx, Labels: labels,
		Reader: reader, Writer: writer, stop: make(chan struct{}),
	}
	if s.Reader != nil {
		s.readerStopped = make(chan struct{}, 1)
	}
	if s.Writer != nil {
		s.writerStopped = make(chan struct{}, 1)
	}
	return s
}

// Start starts the reader/writer goroutines (if any). Does nothing if they
// have been started already.
func (s *Sock) Start() {
	if !s.running {
		if s.Reader != nil {
			go s.Reader(s, s.stop, s.readerStopped)
		}
		if s.Writer != nil {
			go s.Writer(s, s.stop, s.writerStopped)
		}
		s.running = true
		log.Info("Sock routines started", "addr", s.Conn.LocalAddr())
	}
}

// Stop stops the running reader/writer goroutines (if any) and waits until the
// routines are stopped before returing to the caller.
func (s *Sock) Stop() {
	if s.running {
		log.Debug("Sock routines stopping", "addr", s.Conn.LocalAddr())
		close(s.stop)
		s.Ring.Close()
		if err := s.Conn.Close(); err != nil {
			log.Error("Error stopping socket", "err", common.FmtError(err))
		}
		if s.Writer != nil {
			<-s.writerStopped
		}
		if s.Reader != nil {
			<-s.readerStopped
		}
		s.running = false
		log.Info("Sock routines stopped", "addr", s.Conn.LocalAddr())
	}
}
