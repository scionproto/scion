// Copyright 2016 ETH Zurich
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

// This file handles IO using the POSIX(/BSD) socket API.

package main

import (
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/go/border/internal/metrics"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/underlay/conn"
)

const (
	// Number of free packet buffers to request for input.
	inputBufCnt = 32
	// Number of packets to read in a single ReadBatch call.
	inputBatchCnt = 16 // Must be <= inputBufCnt
	// If there are fewer than inputLowBufCnt free packet buffers, request more.
	inputLowBufCnt = 4
	// Number of packet buffers to request for output.
	outputBufCnt = 32
	// Number of packets to write in a single WriteBatch call.
	outputBatchCnt = 32 // Must be <= outputBufCnt
)

func (r *Router) posixInput(s *rctx.Sock, stop, stopped chan struct{}) {
	defer log.HandlePanic()
	defer close(stopped)
	dst := s.Conn.LocalAddr()
	log.Info("posixInput starting", "addr", dst)
	defer log.Info("posixInput stopping", "addr", dst)
	pkts := make(ringbuf.EntryList, 0, inputBufCnt)
	msgs := conn.NewReadMessages(inputBatchCnt)
	readMetas := make([]conn.ReadMeta, inputBatchCnt)
	var err error

	l := metrics.IntfLabels{Intf: s.Label, NeighIA: s.NeighIA}
	// Pre-calculate metrics
	inputPkts := metrics.Input.Pkts(l)
	inputBytes := metrics.Input.Bytes(l)
	inputPktSize := metrics.Input.PktSize(l)
	inputReads := metrics.Input.Reads(l)
	inputReadErrs := metrics.Input.ReadErrors(l)
	inputRcvOvfl := metrics.Input.RcvOvfl(l)
	inputLatency := metrics.Input.Latency(l)
	procPktTime := metrics.Process.Duration(l)

	// Called when the packet's reference count hits 0.
	free := func(rp *rpkt.RtrPkt) {
		// Protect against system clock moving backwards
		t := time.Since(rp.TimeIn).Seconds()
		if t < 0 {
			t = 0
		}
		procPktTime.Add(t)
		rp.Reset()
		r.freePkts.Write(ringbuf.EntryList{rp}, true)
	}

Top:
	for {
		select {
		case <-stop:
			break Top
		default:
		}
		var ok bool
		if pkts, ok = r.posixPrepInput(pkts, msgs); !ok {
			break
		}
		inputReads.Inc()
		toRead := min(len(pkts), inputBatchCnt)
		var pktsRead int
		// Loop until a read succeeds, or a non-trivial error occurs
		if pktsRead, err = r.posixInputRead(msgs[:toRead], readMetas[:toRead], s.Conn); err != nil {
			inputReadErrs.Inc()
			log.Error("Error reading from socket", "socket", dst, "err", err)
			// The most likely reason for errors is that the socket has
			// been closed, so jump back to the top to see if the stop
			// signal has been sent.
			continue Top
		}
		inputPkts.Add(float64(pktsRead))
		// Grab current router context to attach to this batch of packets.
		ctx := rctx.Get()
		if assert.On {
			assert.Must(pktsRead > 0, "Pktsread must be non-zero")
		}
		// Loop over all read packets and set their metadata
		for i := 0; i < pktsRead; i++ {
			rp := pkts[i].(*rpkt.RtrPkt)
			msg := msgs[i]
			meta := readMetas[i]
			rp.Ctx = ctx
			rp.DirFrom = s.Dir
			rp.Free = free // Set free callback.
			if i == pktsRead-1 {
				// Only bother setting the Gauge once per ReadBatch. Use
				// the last read as internally the kernel calls recvmsg
				// multiple times, so it will have the latest value.
				inputRcvOvfl.Set(float64(meta.RcvOvfl))
			}
			inputLatency.Add(meta.ReadDelay.Seconds())
			rp.TimeIn = meta.Recvd
			rp.Raw = rp.Raw[:msg.N] // Set the length of the slice
			rp.Ingress.Dst = dst
			rp.Ingress.IfLabel = s.Label
			// Make a copy, as meta.Src will be overwritten.
			src := meta.Src
			rp.Ingress.Src = src
			rp.Ingress.IfID = s.Ifid
			inputBytes.Add(float64(msg.N))
			inputPktSize.Observe(float64(msg.N))
		}
		for written := 0; written < pktsRead; {
			wn, _ := s.Ring.Write(pkts[written:pktsRead], true)
			written += wn
		}
		// Move unused pkts to the start.
		copied := copy(pkts, pkts[pktsRead:])
		pkts = pkts[:copied]
	}
	// Return any unused buffers.
	r.freePkts.Write(pkts, true)
}

// posixPrepInput refills pkts if it's below inputLowBufCnt, and sets the msgs
// Buffers references to point to the corresponding buffers in pkts.
func (r *Router) posixPrepInput(pkts ringbuf.EntryList,
	msgs []ipv4.Message) (ringbuf.EntryList, bool) {

	if len(pkts) < inputLowBufCnt {
		before := len(pkts)
		pkts = pkts[:cap(pkts)]
		// fetch fresh buffers to the end of pkts
		n, _ := r.freePkts.Read(pkts[before:], true)
		if n < 0 {
			pkts = pkts[:before]
			return pkts, false
		}
		pkts = pkts[:before+n]
	}
	// setup msg references
	for i := range pkts {
		if i == inputBatchCnt {
			break
		}
		rp := pkts[i].(*rpkt.RtrPkt)
		msgs[i].Buffers[0] = rp.Raw
	}
	return pkts, true
}

func (r *Router) posixInputRead(msgs []ipv4.Message, metas []conn.ReadMeta,
	c conn.Conn) (int, error) {
	// Loop until a read succeeds, or a non-trivial error occurs
	for {
		n, err := c.ReadBatch(msgs, metas)
		if err != nil && isSyscallErrno(err, syscall.ECONNREFUSED) {
			// As we are using a connected UDP socket for interface sockets,
			// any ECONNREFUSED errors that happen while sending to the
			// neighbouring BR show up as read errors on the socket. As these
			// do not indicate a problem with this BR, these errors should not
			// be counted, and should not increment the read counter.
			// TODO(kormat): consider having a conn refused error count
			// for external interfaces.
			continue
		}
		return n, err
	}
}

func (r *Router) posixOutput(s *rctx.Sock, _, stopped chan struct{}) {
	defer log.HandlePanic()
	defer close(stopped)
	src := s.Conn.LocalAddr()
	dst := s.Conn.RemoteAddr()
	log.Info("posixOutput starting", "addr", src)
	defer log.Info("posixOutput stopping", "addr", src)
	epkts := make(ringbuf.EntryList, 0, outputBufCnt)
	msgs := conn.NewWriteMessages(outputBatchCnt)

	// Pre-calculate metrics
	l := metrics.IntfLabels{Intf: s.Label, NeighIA: s.NeighIA}
	outputPkts := metrics.Output.Pkts(l)
	outputBytes := metrics.Output.Bytes(l)
	outputPktSize := metrics.Output.PktSize(l)
	outputWrites := metrics.Output.Writes(l)
	outputWriteErrs := metrics.Output.WriteErrors(l)
	outputWriteLatency := metrics.Output.Duration(l)

	// This loop is exited in two cases:
	// 1. When the the ring is closed and fully drained.
	// 2. When a non-recoverable error happens.
	for {
		var bytes int // Needs to be declared before goto
		var t float64 // Needs to be declared before goto
		var ok bool
		if epkts, ok = r.posixPrepOutput(epkts, msgs, s.Ring, dst != nil); !ok {
			break
		}
		toWrite := min(len(epkts), outputBatchCnt)
		start := time.Now()
		var err error
		var pktsWritten int
		if pktsWritten, err = s.Conn.WriteBatch(msgs[:toWrite]); err != nil {
			outputWriteErrs.Inc()
			log.Error("Error sending packet(s)", "src", src, "err", err)
			// If some packets were still sent, continue processing. Otherwise:
			if pktsWritten <= 0 {
				// If we know the error is temporary, retry sending, otherwise drop
				// the current batch and move on.
				if common.IsTemporaryErr(err) {
					continue
				}
				// Before dropping the packets, we have to return them to the freelist.
				releasePkts(epkts[:toWrite])
				// Drop packets from the failed write attempt.
				epkts = shiftUnwrittenPkts(epkts, toWrite)
				if isRecoverableErr(err) {
					continue
				}
				// Shutdown writer if the error is non-recoverable.
				fatal.Fatal(serrors.WrapStr("shutdown on irrecoverable error to avoid broken state",
					err, "ifid", s.Ifid))
			}
		}
		t = time.Since(start).Seconds()
		bytes = 0
		for i := 0; i < pktsWritten; i++ {
			rp := epkts[i].(*rpkt.EgressRtrPkt).Rp
			msg := &msgs[i]
			if msg.N != len(rp.Raw) {
				rp.Error("Unable to write full packet", "len", len(rp.Raw), "written", msg.N)
			}
			bytes += msg.N
			outputPktSize.Observe(float64(msg.N))
			rp.Release()   // Release inner RtrPkt entry
			epkts[i] = nil // Clear EgressRtrPkt reference
		}
		outputWriteLatency.Add(t)
		outputPkts.Add(float64(pktsWritten))
		outputBytes.Add(float64(bytes))
		outputWrites.Inc()
		epkts = shiftUnwrittenPkts(epkts, pktsWritten)
	}
	// Release any remaining unsent pkts.
	releasePkts(epkts)
	epkts = epkts[:0]
}

// posixPrepOutput fetches new packets if epkts is empty, and sets the msgs
// Buffers and Addr based on the corresponding entries in epkts. The second return
// value is false, if the underlying ring is closed and drained.
func (r *Router) posixPrepOutput(epkts ringbuf.EntryList, msgs []ipv4.Message,
	ring *ringbuf.Ring, connected bool) (ringbuf.EntryList, bool) {

	if len(epkts) == 0 {
		epkts = epkts[:cap(epkts)]
		n, _ := ring.Read(epkts, true)
		if n < 0 {
			return epkts[:0], false
		}
		epkts = epkts[:n]
	}
	// setup msgs
	for i := range epkts {
		if i == outputBatchCnt {
			break
		}
		erp := epkts[i].(*rpkt.EgressRtrPkt)
		rp := erp.Rp
		msgs[i].Buffers[0] = rp.Raw
		if !connected {
			// Unconnected socket, use supplied address
			msgs[i].Addr.(*net.UDPAddr).IP = erp.Dst.IP
			msgs[i].Addr.(*net.UDPAddr).Port = int(erp.Dst.Port)
		}
	}
	return epkts, true
}

// releasePkts releases all pkts in the entry list.
func releasePkts(epkts ringbuf.EntryList) {
	for _, epkt := range epkts {
		epkt.(*rpkt.EgressRtrPkt).Rp.Release()
	}
}

// shiftUnwrittenPkts moves the unwritten packets to the start.
func shiftUnwrittenPkts(epkts ringbuf.EntryList, pktsWritten int) ringbuf.EntryList {
	copied := copy(epkts, epkts[pktsWritten:])
	return epkts[:copied]
}

// isRecoverableErr checks whether an non-temporary error is recoverable.
func isRecoverableErr(err error) bool {
	switch {
	case isSyscallErrno(err, syscall.ECONNREFUSED),
		isSyscallErrno(err, syscall.ENETUNREACH),
		isSyscallErrno(err, syscall.EHOSTUNREACH),
		isSyscallErrno(err, syscall.EPERM):
		return true
	default:
		return false
	}
}

func isSyscallErrno(err error, errno syscall.Errno) bool {
	var target syscall.Errno
	if errors.As(err, &target) {
		return target == errno
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
