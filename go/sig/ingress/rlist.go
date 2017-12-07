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

package ingress

import (
	"bytes"
	"container/list"
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/sig/metrics"
	"github.com/scionproto/scion/go/sig/sigcmn"
)

// ReassemblyList is used to keep a doubly linked list of SIG frames that are
// outstanding for reassembly. The frames kept in the reassambly list sorted by
// their sequence numbers. There is always one reassembly list per epoch to
// ensure that sequence numbers are monotonically increasing.
type ReassemblyList struct {
	epoch             int
	capacity          int
	markedForDeletion bool
	entries           *list.List
	buf               *bytes.Buffer
}

// NewReassemblyList returns a ReassemblyList object for the given epoch and with
// given maximum capacity.
func NewReassemblyList(epoch int, capacity int) *ReassemblyList {
	list := &ReassemblyList{
		epoch:             epoch,
		capacity:          capacity,
		markedForDeletion: false,
		entries:           list.New(),
		buf:               bytes.NewBuffer(make(common.RawBytes, 0, frameBufCap)),
	}
	return list
}

// Insert inserts a frame into the reassembly list.
// After inserting the frame at the correct position, Insert tries to reassemble packets
// that involve the newly added frame. Completely processed frames get removed from the
// list and released to the pool of frame buffers.
func (l *ReassemblyList) Insert(frame *FrameBuf) {
	// If this is the first frame, write all complete packets to the wire and
	// add the frame to the reassembly list if it contains a fragment at the end.
	if l.entries.Len() == 0 {
		l.insertFirst(frame)
		return
	}
	first := l.entries.Front()
	firstFrame := first.Value.(*FrameBuf)
	// Check whether frame is too old.
	if frame.seqNr < firstFrame.seqNr {
		metrics.FramesTooOld.Inc()
		frame.Release()
		return
	}
	last := l.entries.Back()
	lastFrame := last.Value.(*FrameBuf)
	// Check if the frame is a duplicate.
	if frame.seqNr >= firstFrame.seqNr && frame.seqNr <= lastFrame.seqNr {
		log.Error("Received duplicate frame.", "epoch", l.epoch, "seqNr", frame.seqNr,
			"currentOldest", firstFrame.seqNr, "currentNewest", lastFrame.seqNr)
		metrics.FramesDuplicated.Inc()
		frame.Release()
		return
	}
	// If there is a gap between this frame and the last in the reassembly list,
	// remove all packets from the reassembly list and only add this frame.
	if frame.seqNr > lastFrame.seqNr+1 {
		log.Info(fmt.Sprintf("Detected dropped frame(s). Discarding %d frames.", l.entries.Len()),
			"epoch", l.epoch, "segNr", frame.seqNr, "currentNewest", lastFrame.seqNr)
		metrics.FrameDiscardEvents.Inc()
		metrics.FramesDiscarded.Add(float64(frame.seqNr - lastFrame.seqNr - 1))
		l.removeAll()
		l.insertFirst(frame)
		return
	}
	// Check if we have capacity.
	if l.entries.Len() == l.capacity {
		log.Warn("Reassembly list reached maximum capacity", "epoch", l.epoch, "cap", l.capacity)
		l.removeAll()
		l.insertFirst(frame)
		return
	}
	l.entries.PushBack(frame)
	l.tryReassemble()
}

// insertFirst handles the case when the reassembly list is empty and a frame needs
// to be inserted.
func (l *ReassemblyList) insertFirst(frame *FrameBuf) {
	frame.ProcessCompletePkts()
	if frame.frag0Start != 0 {
		l.entries.PushBack(frame)
	} else {
		frame.Release()
	}
}

// tryReassemble checks if a packet can be reassembled from the reassembly list.
func (l *ReassemblyList) tryReassemble() {
	if l.entries.Len() < 2 {
		return
	}
	start := l.entries.Front()
	startFrame := start.Value.(*FrameBuf)
	if startFrame.frag0Start == 0 {
		// Should never happen.
		log.Error("First frame in reassembly list does not contain a packet start.",
			"frame", startFrame.String())
		// Safest to remove all frames in the list.
		l.removeAll()
		return
	}
	bytes := startFrame.frameLen - startFrame.frag0Start
	canReassemble := false
	framingError := false
	for e := start.Next(); e != nil; e = e.Next() {
		currFrame := e.Value.(*FrameBuf)
		// Add number of bytes contained in this frame. This potentially adds
		// too much, but we are only using it to detect whether we potentially
		// have everything we need.
		bytes += (currFrame.frameLen - 8)
		// Check if we have found all frames.
		if bytes >= startFrame.pktLen {
			canReassemble = true
			break
		}
		if currFrame.index != 0 {
			log.Error("Framing error occurred. Not enough bytes to reassemble packet",
				"startFrame", startFrame.String(), "currFrame", currFrame.String())
			framingError = true
			break
		}
	}
	if canReassemble {
		l.collectAndWrite()
	} else if framingError {
		l.removeBefore(l.entries.Back())
	}
}

// collectAndWrite reassembles the packet in the reassembly list and writes it
// out to the buffer. It will also write every complete packet in the last frame.
func (l *ReassemblyList) collectAndWrite() {
	start := l.entries.Front()
	startFrame := start.Value.(*FrameBuf)
	// Reset reassembly buffer.
	l.buf.Reset()
	// Collect the start of the packet.
	pktLen := startFrame.pktLen
	l.buf.Write(startFrame.raw[startFrame.frag0Start:startFrame.frameLen])
	// We cannot process the startframe any further.
	startFrame.SetProcessed()
	// Collect rest.
	var frame *FrameBuf
	for e := start.Next(); l.buf.Len() < pktLen && e != nil; e = e.Next() {
		frame = e.Value.(*FrameBuf)
		missingBytes := pktLen - l.buf.Len()
		l.buf.Write(
			frame.raw[sigcmn.SIGHdrSize:intMin(missingBytes+sigcmn.SIGHdrSize, frame.frameLen)],
		)
		frame.fragNProcessed = true
	}
	// Check length of the reassembled packet.
	if l.buf.Len() != pktLen {
		log.Error("Packet len for reassembled packet does not match header",
			"expected", pktLen, "have", l.buf.Len())
	} else {
		// Write the packet to the wire.
		if err := send(l.buf.Bytes()); err != nil {
			cerr := err.(*common.CError)
			log.Error("Unable to send reassembled packet; "+cerr.Desc, cerr.Ctx...)
		}
	}
	// Process the complete packets in the last frame
	frame.ProcessCompletePkts()
	// Remove all processed frames from the list.
	l.removeProcessed()
}

func (l *ReassemblyList) removeEntry(e *list.Element) {
	frame := e.Value.(*FrameBuf)
	frame.Release()
	l.entries.Remove(e)
}

func (l *ReassemblyList) removeOldest() {
	l.removeEntry(l.entries.Front())
}

func (l *ReassemblyList) removeProcessed() {
	var next *list.Element
	for e := l.entries.Front(); e != nil; e = next {
		frame := e.Value.(*FrameBuf)
		next = e.Next()
		if frame.Processed() {
			l.removeEntry(e)
		}
	}
}

func (l *ReassemblyList) removeAll() {
	l.removeBefore(nil)
}

func (l *ReassemblyList) removeBefore(ele *list.Element) {
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
