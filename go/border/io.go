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

	"github.com/netsec-ethz/scion/go/border/context"
	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

type PosixInputFuncArgs struct {
	Router   *Router
	Conn     *net.UDPConn
	DirFrom  rpkt.Dir
	Ifids    []spath.IntfID
	Labels   prometheus.Labels
	StopChan chan struct{}
}

type PosixInputFunc func(args *PosixInputFuncArgs)

type PosixInput struct {
	Args *PosixInputFuncArgs
	Func PosixInputFunc
}

func (pi *PosixInput) Start() {
	go pi.Func(pi.Args)
}

func (pi *PosixInput) Stop() {
	close(pi.Args.StopChan)
}

// ReadPosixInput reads packets from a single POSIX(/BSD) socket. It retrieves
// buffers via getPktBuf, and fills in some important packet metadata such as
// the overlay source/destination addresses, the direction the packet came
// from, and the list of interfaces that it could belong to (as some sockets
// may be associated with more than one interface).
func readPosixInput(args *PosixInputFuncArgs) {
	defer liblog.PanicLog()
	log.Info("Listening", "addr", args.Conn.LocalAddr())
	dst := args.Conn.LocalAddr().(*net.UDPAddr)
	// Create a new rpkt buffer to be used by this input routine.
	rp := rpkt.NewRtrPkt()
	for { // Run until stop signal is received.
		select {
		default:
			metrics.InputLoops.With(args.Labels).Inc()
			// Get current router context for this packet.
			rp.Ctx = context.GetContext()
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
			args.Router.processPacket(rp)
			metrics.PktProcessTime.Add(monotime.Since(rp.TimeIn).Seconds())
			// Reset rpkt buffer so it can be reused.
			rp.Reset()
		case <-args.StopChan:
			log.Info("Input routine stopped for", "addr", args.Conn.LocalAddr())
			return
		}
	}
}

type posixOutputFunc func(common.RawBytes, *net.UDPAddr) (int, error)

// writePosixOutput writes packets to a POSIX(/BSD) socket using the provided
// function (a wrapper around net.UDPConn.WriteToUDP or net.UDPConn.Write).
func writePosixOutput(labels prometheus.Labels,
	oo context.OutputObj, dst *net.UDPAddr, f posixOutputFunc) {
	start := monotime.Now()
	raw := oo.Bytes()
	if count, err := f(raw, dst); err != nil {
		oo.LogError("Error sending packet", "err", err, "dst", dst)
		return
	} else if count != len(raw) {
		oo.LogError("Unable to write full packet", "len", len(raw), "written", count)
		return
	}
	t := monotime.Since(start).Seconds()
	metrics.OutputProcessTime.With(labels).Add(t)
	metrics.BytesSent.With(labels).Add(float64(len(raw)))
	metrics.PktsSent.With(labels).Inc()
}
