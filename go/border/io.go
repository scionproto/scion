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
	"os"
	"syscall"
	"time"

	"github.com/gavv/monotime"
	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/border/metrics"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay/conn"
	"github.com/scionproto/scion/go/lib/ringbuf"
)

func (r *Router) posixInput(s *rctx.Sock, stop, stopped chan struct{}) {
	defer liblog.LogPanicAndExit()
	defer close(stopped)
	dst := s.Conn.LocalAddr()
	log.Debug("posixInput starting", "addr", dst)
	pkts := make(ringbuf.EntryList, 32)
	var length int
	var cmeta *conn.ReadMeta
	var err error
	var sock = s.Labels["sock"]

	// Pre-calculate metrics
	inputPkts := metrics.InputPkts.With(s.Labels)
	inputBytes := metrics.InputBytes.With(s.Labels)
	inputPktSize := metrics.InputPktSize.With(s.Labels)
	inputReads := metrics.InputReads.With(s.Labels)
	inputReadErrs := metrics.InputReadErrors.With(s.Labels)
	inputRcvOvfl := metrics.InputRcvOvfl.With(s.Labels)
	inputLatency := metrics.InputLatency.With(s.Labels)
	procPktTime := metrics.ProcessPktTime.With(s.Labels)

	// Called when the packet's reference count hits 0.
	free := func(rp *rpkt.RtrPkt) {
		procPktTime.Add(monotime.Since(rp.TimeIn).Seconds())
		rp.Reset()
		r.freePkts.Write(ringbuf.EntryList{rp}, true)
	}

Top:
	for {
		select {
		case <-stop:
			log.Debug("posixInput stopping", "addr", dst)
			return
		default:
		}
		n, _ := r.freePkts.Read(pkts, true)
		for i := 0; i < n; i++ {
			rp := pkts[i].(*rpkt.RtrPkt)
			rp.Ctx = rctx.Get() // Get current router context for this packet.
			rp.DirFrom = s.Dir
			rp.Free = free // Set free callback.
			inputReads.Inc()
			for {
				length, cmeta, err = s.Conn.Read(rp.Raw)
				if err == nil {
					break // No error, process packet.
				}
				if isConnRefused(err) {
					// As we are using a connected UDP socket for interface
					// sockets, any ECONNREFUSED errors that happen while
					// sending to the neighbouring BR show up as read errors on
					// the socket. As these do not indicate a problem with this BR,
					// these errors should not be counted, and should not
					// increment the read counter.
					// TODO(kormat): consider having a conn refused error count
					// for external interfaces.
					continue
				}
				inputReadErrs.Inc()
				log.Error("Error reading from socket", "socket", dst, "err", err)
				// Release all unwritten buffers, including the current one:
				for j := i; j < n; j++ {
					rp := pkts[j].(*rpkt.RtrPkt)
					free(rp)
				}
				// The most likely reason for errors is that the socket has
				// been closed, so jump back to the top to see if the stop
				// signal has been sent.
				continue Top
			}
			inputRcvOvfl.Set(float64(cmeta.RcvOvfl))
			inputLatency.Add((cmeta.Read - cmeta.Recvd).Seconds())
			rp.TimeIn = cmeta.Recvd
			rp.Raw = rp.Raw[:length] // Set the length of the slice
			rp.Ingress.Dst = dst
			// Make a copy, as cmeta.Src will be overwritten by the next packet.
			src := *cmeta.Src
			rp.Ingress.Src = &src
			rp.Ingress.IfIDs = s.Ifids
			rp.Ingress.LocIdx = s.LocIdx
			rp.Ingress.Sock = sock
			inputPkts.Inc()
			inputBytes.Add(float64(length))
			inputPktSize.Observe(float64(length))
			s.Ring.Write(ringbuf.EntryList{pkts[i]}, true)
			// Clear RtrPkt reference
			pkts[i] = nil
		}
	}
}

func (r *Router) posixOutput(s *rctx.Sock, _, stopped chan struct{}) {
	defer liblog.LogPanicAndExit()
	defer close(stopped)
	src := s.Conn.LocalAddr()
	log.Info("posixOutput starting", "addr", src)
	epkts := make(ringbuf.EntryList, 32)

	// Pre-calculate metrics
	outputPkts := metrics.OutputPkts.With(s.Labels)
	outputBytes := metrics.OutputBytes.With(s.Labels)
	outputPktSize := metrics.OutputPktSize.With(s.Labels)
	outputWrites := metrics.OutputWrites.With(s.Labels)
	outputWriteErrs := metrics.OutputWriteErrors.With(s.Labels)
	outputWriteLatency := metrics.OutputWriteLatency.With(s.Labels)

	var count int
	var err error
	var start time.Duration
	var t float64
	for {
		n, _ := s.Ring.Read(epkts, true)
		if n < 0 {
			log.Debug("posixOutput stopping", "addr", src)
			return
		}
		for i := 0; i < n; i++ {
			erp := epkts[i].(*rpkt.EgressRtrPkt)
			rp := erp.Rp
			// This becomes meaningful when we can write multiple packets at once:
			outputWrites.Add(1)
			start = monotime.Now()
			if count, err = s.Conn.WriteTo(rp.Raw, erp.Dst); err != nil {
				outputWriteErrs.Inc()
				rp.Error("Error sending packet", "err", err, "dst", erp.Dst)
				goto End
			}
			if count != len(rp.Raw) {
				rp.Error("Unable to write full packet", "len", len(rp.Raw), "written", count)
			}
			t = monotime.Since(start).Seconds()
			outputWriteLatency.Add(t)
			outputPkts.Inc()
			outputBytes.Add(float64(count))
			outputPktSize.Observe(float64(count))
		End:
			rp.Release()   // Release inner RtrPkt entry
			epkts[i] = nil // Clear EgressRtrPkt reference
		}
	}
}

func isConnRefused(err error) bool {
	netErr, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	osErr, ok := netErr.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	return osErr.Err == syscall.ECONNREFUSED
}
