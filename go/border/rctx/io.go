// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"time"

	"github.com/scionproto/scion/go/border/brconf"
	"github.com/scionproto/scion/go/border/internal/metrics"
	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
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
	// Ifid is the interface ID associated with a connection.
	Ifid common.IFIDType
	// Label is the interface label
	Label string
	// NeighIA is the interface remote IA
	NeighIA string
	// Reader is an optional function that reads from Sock.Ring. It is spawned
	// in a go routine when Sock.Start() is called.
	Reader SockFunc
	// Writer is an optional function that writes to Sock.Ring. It is spawned
	// in a go routine when Sock.Start() is called.
	Writer SockFunc
	// Type is the type of the socket.
	Type          brconf.SockType
	stop          chan struct{}
	readerStopped chan struct{}
	writerStopped chan struct{}
	running       bool
	started       bool
}

func NewSock(ring *ringbuf.Ring, conn conn.Conn, dir rcmn.Dir, ifid common.IFIDType,
	neighIA string, reader, writer SockFunc, sockType brconf.SockType) *Sock {

	log.Debug("New Socket", "dir", dir, "ifid", ifid, "neighIA", neighIA, "sockType", sockType)

	s := &Sock{
		Ring:    ring,
		Conn:    conn,
		Dir:     dir,
		Ifid:    ifid,
		Label:   metrics.IntfToLabel(ifid),
		NeighIA: neighIA,
		Reader:  reader,
		Writer:  writer,
		stop:    make(chan struct{}),
		Type:    sockType,
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
		// Restarting is not permitted because the stop/stopped channels are closed.
		if assert.On {
			assert.Must(!s.started, "Socket must not be restarted after being closed")
		}
		if s.Reader != nil {
			go func() {
				defer log.HandlePanic()
				s.Reader(s, s.stop, s.readerStopped)
			}()
		}
		if s.Writer != nil {
			go func() {
				defer log.HandlePanic()
				s.Writer(s, s.stop, s.writerStopped)
			}()
		}
		s.running = true
		s.started = true
		log.Info("Sock routines started", "addr", s.Conn.LocalAddr(), "dir", s.Dir,
			"ifid", s.Ifid, "type", s.Type)
	}
}

// Stop stops the running reader/writer goroutines (if any) and waits until the
// routines are stopped before returning to the caller.
func (s *Sock) Stop() {
	if s.running {
		log.Debug("Sock routines stopping", "addr", s.Conn.LocalAddr(), "dir", s.Dir,
			"ifid", s.Ifid, "type", s.Type)
		// The order of the sequence below is important:
		// Close the Sock, which effectively only signals the Reader to finish.
		close(s.stop)
		// If there is no traffic, the Reader might be blocked reading from the socket, so
		// unblock the reader with deadline
		s.Conn.SetReadDeadline(time.Now())
		if s.Reader != nil {
			<-s.readerStopped
		}
		// Close the ringbuf which in turn will make the Writer to close after it has processed
		// all packets in the ringbuf.
		// This is the only way to signal the Writer to finish.
		s.Ring.Close()
		if s.Writer != nil {
			<-s.writerStopped
		}
		// Close the posix sockets.
		if err := s.Conn.Close(); err != nil {
			log.Error("Error stopping socket", "addr", s.Conn.LocalAddr(), "err", err)
		}
		s.running = false
		log.Info("Sock routines stopped", "addr", s.Conn.LocalAddr())
	} else if !s.started {
		s.Ring.Close()
		if err := s.Conn.Close(); err != nil {
			log.Error("Error stopping socket", "addr", s.Conn.LocalAddr(), "err", err)
		}
		log.Info("Non-started sock stopped", "addr", s.Conn.LocalAddr())
	}
}

func (s *Sock) Running() bool {
	return s.running
}

func (s *Sock) Started() bool {
	return s.started
}
