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

// This file handles IO using the POSIX(/BSD) socket API.

package main

import (
	"net"

	"github.com/gavv/monotime"
	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rctx"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

// PosixInputFuncArgs defines the arguments needed by a PosixInputFunc.
type PosixInputFuncArgs struct {
	// ProcessPacket is the main packet processing routine.
	ProcessPacket func(*rpkt.RtrPkt)
	// Conn is the connection the input function is listening on.
	Conn *net.UDPConn
	// DirFrom is the direction of the incoming packets.
	DirFrom rpkt.Dir
	// Ifids is a slice of interface IDs that are served by this input function.
	Ifids []spath.IntfID
	// Labels holds the exported prometheus labels.
	Labels prometheus.Labels
	// StopChan is used to stop the input function.
	StopChan chan struct{}
	// StoppedChan is used to inform the stopper, when the input function has stopped.
	StoppedChan chan struct{}
}

type PosixInputFunc func(args *PosixInputFuncArgs)

// PosixInput represents an input goroutine for a Posix socket. It implements
// the rctx.IOCtrl interface.
type PosixInput struct {
	Args    *PosixInputFuncArgs
	Func    PosixInputFunc
	running bool
}

// Start starts the input goroutine. Does nothing if it is already running.
func (pi *PosixInput) Start() {
	if !pi.running {
		go pi.Func(pi.Args)
		pi.running = true
		log.Info("Input routing started", "addr", pi.Args.Conn.LocalAddr())
	}
}

// Stop stops a running input goroutine and waits until the routine stopped
// before returing to the caller.
func (pi *PosixInput) Stop() {
	if pi.running {
		close(pi.Args.StopChan)
		// Wait for the goroutine to stop.
		<-pi.Args.StoppedChan
		pi.running = false
		log.Info("Input routine stopped", "addr", pi.Args.Conn.LocalAddr())
	}
}

// ReadPosixInput reads packets from a single POSIX(/BSD) socket. It retrieves
// buffers via getPktBuf, and fills in some important packet metadata such as
// the overlay source/destination addresses, the direction the packet came
// from, and the list of interfaces that it could belong to (as some sockets
// may be associated with more than one interface).
func readPosixInput(args *PosixInputFuncArgs) {
	defer liblog.PanicLog()
	defer close(args.StoppedChan)
	log.Info("Listening", "addr", args.Conn.LocalAddr())
	dst := args.Conn.LocalAddr().(*net.UDPAddr)
	// Create a new rpkt buffer to be used by this input routine.
	rp := rpkt.NewRtrPkt()
	for { // Run until stop signal is received.
		select {
		default:
			metrics.InputLoops.With(args.Labels).Inc()
			// Get current router context for this packet.
			rp.Ctx = rctx.Get()
			rp.DirFrom = args.DirFrom
			start := monotime.Now()
			length, src, err := args.Conn.ReadFromUDP(rp.Raw)
			if err != nil {
				log.Error("Error reading from socket", "socket", dst, "err", err)
				continue
			}
			t := monotime.Since(start).Seconds()
			metrics.InputProcessTime.With(args.Labels).Add(t)
			rp.TimeIn = monotime.Now()
			rp.Raw = rp.Raw[:length] // Set the length of the slice
			rp.Ingress.Dst = dst
			rp.Ingress.Src = src
			rp.Ingress.IfIDs = args.Ifids
			metrics.PktsRecv.With(args.Labels).Inc()
			metrics.BytesRecv.With(args.Labels).Add(float64(length))
			// TODO(kormat): experiment with performance by calling processPacket directly instead.
			args.ProcessPacket(rp)
			metrics.PktProcessTime.Add(monotime.Since(rp.TimeIn).Seconds())
			// Reset rpkt buffer so it can be reused.
			rp.Reset()
		case <-args.StopChan:
			if err := args.Conn.Close(); err != nil {
				log.Error("Error closing connection", "conn", args.Conn, "err", err.Error())
			}
			return
		}
	}
}

type posixOutputFunc func(common.RawBytes, *net.UDPAddr) (int, error)

// writePosixOutput writes packets to a POSIX(/BSD) socket using the provided
// function (a wrapper around net.UDPConn.WriteToUDP or net.UDPConn.Write).
func writePosixOutput(labels prometheus.Labels,
	oo rctx.OutputObj, dst *net.UDPAddr, f posixOutputFunc) {
	start := monotime.Now()
	raw := oo.Bytes()
	if count, err := f(raw, dst); err != nil {
		oo.Error("Error sending packet", "err", err, "dst", dst)
		return
	} else if count != len(raw) {
		oo.Error("Unable to write full packet", "len", len(raw), "written", count)
		return
	}
	t := monotime.Since(start).Seconds()
	metrics.OutputProcessTime.With(labels).Add(t)
	metrics.BytesSent.With(labels).Add(float64(len(raw)))
	metrics.PktsSent.With(labels).Inc()
}
