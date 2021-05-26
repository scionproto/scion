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

package dataplane

import (
	"bytes"
	"container/list"
	"fmt"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
)

// reassemblyList is used to keep a doubly linked list of SIG frames that are
// outstanding for reassembly. The frames kept in the reassambly list sorted by
// their sequence numbers. There is always one reassembly list per epoch to
// ensure that sequence numbers are monotonically increasing.
type reassemblyList struct {
	epoch             int
	capacity          int
	snd               ingressSender
	markedForDeletion bool
	entries           *list.List
	buf               *bytes.Buffer
	tooOld            metrics.Counter
	duplicate         metrics.Counter
	evicted           metrics.Counter
	invalid           metrics.Counter
}

// newReassemblyList returns a ReassemblyList object for the given epoch and with
// given maximum capacity.
func newReassemblyList(epoch int, capacity int, s ingressSender,
	framesDiscarded metrics.Counter) *reassemblyList {

	list := &reassemblyList{
		epoch:             epoch,
		capacity:          capacity,
		snd:               s,
		markedForDeletion: false,
		entries:           list.New(),
		buf:               bytes.NewBuffer(make([]byte, 0, frameBufCap)),
	}
	if framesDiscarded != nil {
		list.tooOld = framesDiscarded.With("reason", "too_old")
		list.duplicate = framesDiscarded.With("reason", "duplicate")
		list.evicted = framesDiscarded.With("reason", "evicted")
		list.invalid = framesDiscarded.With("reason", "invalid")
	}
	return list
}

// Insert inserts a frame into the reassembly list.
// After inserting the frame at the correct position, Insert tries to reassemble packets
// that involve the newly added frame. Completely processed frames get removed from the
// list and released to the pool of frame buffers.
func (l *reassemblyList) Insert(frame *frameBuf) {
	// If this is the first frame, write all complete packets to the wire and
	// add the frame to the reassembly list if it contains a fragment at the end.
	if l.entries.Len() == 0 {
		l.insertFirst(frame)
		return
	}
	first := l.entries.Front()
	firstFrame := first.Value.(*frameBuf)
	// Check whether frame is too old.
	if frame.seqNr < firstFrame.seqNr {
		increaseCounterMetric(l.tooOld, 1)
		frame.Release()
		return
	}
	last := l.entries.Back()
	lastFrame := last.Value.(*frameBuf)
	// Check if the frame is a duplicate.
	if frame.seqNr >= firstFrame.seqNr && frame.seqNr <= lastFrame.seqNr {
		log.Debug("Received duplicate frame.", "epoch", l.epoch, "seqNr", frame.seqNr,
			"currentOldest", firstFrame.seqNr, "currentNewest", lastFrame.seqNr)
		increaseCounterMetric(l.duplicate, 1)
		frame.Release()
		return
	}
	// If there is a gap between this frame and the last in the reassembly list,
	// remove all packets from the reassembly list and only add this frame.
	if frame.seqNr > lastFrame.seqNr+1 {
		log.Debug(fmt.Sprintf("Detected dropped frame(s). Discarding %d frames.", l.entries.Len()),
			"epoch", l.epoch, "segNr", frame.seqNr, "currentNewest", lastFrame.seqNr)
		increaseCounterMetric(l.evicted, float64(l.entries.Len()))
		l.removeAll()
		l.insertFirst(frame)
		return
	}
	// Check if we have capacity.
	if l.entries.Len() == l.capacity {
		log.Info("Reassembly list reached maximum capacity", "epoch", l.epoch, "cap", l.capacity)
		increaseCounterMetric(l.evicted, float64(l.entries.Len()))
		l.removeAll()
		l.insertFirst(frame)
		return
	}
	l.entries.PushBack(frame)
	l.tryReassemble()
}

// insertFirst handles the case when the reassembly list is empty and a frame needs
// to be inserted.
func (l *reassemblyList) insertFirst(frame *frameBuf) {
	frame.ProcessCompletePkts()
	if frame.frag0Start != 0 {
		l.entries.PushBack(frame)
	} else {
		frame.Release()
	}
}

// tryReassemble checks if a packet can be reassembled from the reassembly list.
func (l *reassemblyList) tryReassemble() {
	if l.entries.Len() < 2 {
		return
	}
	start := l.entries.Front()
	startFrame := start.Value.(*frameBuf)
	if startFrame.frag0Start == 0 {
		// Should never happen.
		log.Error("First frame in reassembly list does not contain a packet start.",
			"frame", startFrame.String())
		// Safest to remove all frames in the list.
		increaseCounterMetric(l.evicted, float64(l.entries.Len()))
		l.removeAll()
		return
	}
	bytes := startFrame.frameLen - startFrame.frag0Start
	canReassemble := false
	framingError := false
	for e := start.Next(); e != nil; e = e.Next() {
		currFrame := e.Value.(*frameBuf)
		// Add number of bytes contained in this frame. This potentially adds
		// too much, but we are only using it to detect whether we potentially
		// have everything we need.
		bytes += (currFrame.frameLen - sigHdrSize)
		// Check if we have found all frames.
		if bytes >= startFrame.pktLen {
			canReassemble = true
			break
		}
		if currFrame.index != 0xffff {
			log.Error("Framing error occurred. Not enough bytes to reassemble packet",
				"startFrame", startFrame.String(), "currFrame", currFrame.String(),
				"pktLen", startFrame.pktLen)
			framingError = true
			break
		}
	}
	if canReassemble {
		l.collectAndWrite()
	} else if framingError {
		increaseCounterMetric(l.invalid, 1)
		l.removeBefore(l.entries.Back())
	}
}

// collectAndWrite reassembles the packet in the reassembly list and writes it
// out to the buffer. It will also write every complete packet in the last frame.
func (l *reassemblyList) collectAndWrite() {
	start := l.entries.Front()
	startFrame := start.Value.(*frameBuf)
	// Reset reassembly buffer.
	l.buf.Reset()
	// Collect the start of the packet.
	pktLen := startFrame.pktLen
	l.buf.Write(startFrame.raw[startFrame.frag0Start:startFrame.frameLen])
	// We cannot process the startframe any further.
	startFrame.SetProcessed()
	// Collect rest.
	var frame *frameBuf
	for e := start.Next(); l.buf.Len() < pktLen && e != nil; e = e.Next() {
		frame = e.Value.(*frameBuf)
		missingBytes := pktLen - l.buf.Len()
		l.buf.Write(
			frame.raw[sigHdrSize:intMin(missingBytes+sigHdrSize, frame.frameLen)],
		)
		frame.fragNProcessed = true
	}
	// Check length of the reassembled packet.
	if l.buf.Len() != pktLen {
		log.Error("Packet len for reassembled packet does not match header",
			"expected", pktLen, "have", l.buf.Len())
	} else {
		// Write the packet to the wire.
		if err := l.snd.send(l.buf.Bytes()); err != nil {
			log.Error("Unable to send reassembled packet", "err", err)
		}
	}
	// Process the complete packets in the last frame
	frame.ProcessCompletePkts()
	// Remove all processed frames from the list.
	l.removeProcessed()
}

func (l *reassemblyList) removeEntry(e *list.Element) {
	frame := e.Value.(*frameBuf)
	frame.Release()
	l.entries.Remove(e)
}

func (l *reassemblyList) removeProcessed() {
	var next *list.Element
	for e := l.entries.Front(); e != nil; e = next {
		frame := e.Value.(*frameBuf)
		next = e.Next()
		if frame.Processed() {
			l.removeEntry(e)
		}
	}
}

func (l *reassemblyList) removeAll() {
	l.removeBefore(nil)
}

func (l *reassemblyList) removeBefore(ele *list.Element) {
	var next *list.Element
	for e := l.entries.Front(); e != ele; e = next {
		next = e.Next()
		l.removeEntry(e)
	}
}

func intMin(x, y int) int {
	if x <= y {
		return x
	}
	return y
}
