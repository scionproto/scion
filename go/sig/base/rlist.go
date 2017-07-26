package base

import (
	"bytes"
	"container/list"
	"fmt"
	"sync"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/metrics"
)

// ReassemblyList is used to keep a doubly linked list of SIG frames that are
// outstanding for reassembly. The frames kept in the reassambly list sorted by
// their sequence numbers. There is always one reassembly list per epoch to
// ensure that sequence numbers are monotonically increasing.
type ReassemblyList struct {
	epoch             int
	capacity          int
	bufPool           *sync.Pool
	markedForDeletion bool
	entries           *list.List
	buf               *bytes.Buffer
}

// NewReassemblyList returns a ReassemblyList object for the given epoch, with given
// maximum capacity and using bufPool to release processed frame buffers into.
func NewReassemblyList(epoch int, capacity int, bufPool *sync.Pool) *ReassemblyList {
	list := &ReassemblyList{
		epoch:             epoch,
		capacity:          capacity,
		bufPool:           bufPool,
		markedForDeletion: false,
		entries:           list.New(),
		buf:               bytes.NewBuffer(make(common.RawBytes, 0, FrameBufCap)),
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
		log.Debug("Discarding frame: too old", "epoch", l.epoch, "seqNr", frame.seqNr,
			"currentOldest", firstFrame.seqNr)
		metrics.FramesTooOld.Inc()
		l.releaseFrame(frame)
		return
	}
	last := l.entries.Back()
	lastFrame := last.Value.(*FrameBuf)
	// Check if the frame is a duplicate.
	if frame.seqNr >= firstFrame.seqNr && frame.seqNr <= lastFrame.seqNr {
		log.Error("Received duplicate frame.", "epoch", l.epoch, "seqNr", frame.seqNr,
			"currentOldest", firstFrame.seqNr, "currentNewest", lastFrame.seqNr)
		metrics.FramesDuplicated.Inc()
		l.releaseFrame(frame)
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
	log.Debug("Adding frame to reassembly list", "frame", frame.String(),
		"listLen", l.entries.Len())
	l.tryReassemble()
}

// insertFirst handles the case when the reassembly list is empty and a frame needs
// to be inserted.
func (l *ReassemblyList) insertFirst(frame *FrameBuf) {
	frame.ProcessCompletePkts()
	if frame.frag0Start != 0 {
		log.Debug("Adding frame to reassembly list", "frame", frame.String(),
			"listLen", l.entries.Len())
		l.entries.PushBack(frame)
	} else {
		l.releaseFrame(frame)
	}
}

// tryReassemble checks if a packet can be reassembled from the reassembly list.
func (l *ReassemblyList) tryReassemble() {
	if l.entries.Len() < 2 {
		return
	}
	log.Debug("Trying to reassemble packet.")
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
	log.Debug("Can reassemble.", "startSeqNr", startFrame.seqNr, "pktLen", startFrame.pktLen,
		"listLen", l.entries.Len())
	// Reset reassembly buffer.
	l.buf.Reset()
	// Collect the start of the packet.
	pktLen := startFrame.pktLen
	log.Debug(fmt.Sprintf("Collecting [%d, %d] from frame %d", startFrame.frag0Start,
		startFrame.frameLen, startFrame.seqNr))
	l.buf.Write(startFrame.raw[startFrame.frag0Start:startFrame.frameLen])
	// We cannot process the startframe any further.
	startFrame.SetProcessed()
	// Collect rest.
	var frame *FrameBuf
	for e := start.Next(); l.buf.Len() < pktLen && e != nil; e = e.Next() {
		frame = e.Value.(*FrameBuf)
		missingBytes := pktLen - l.buf.Len()
		log.Debug(fmt.Sprintf("Collecting [%d, %d] from frame %d", SIGHdrSize,
			min(missingBytes+SIGHdrSize, frame.frameLen), frame.seqNr))
		l.buf.Write(frame.raw[SIGHdrSize:min(missingBytes+SIGHdrSize, frame.frameLen)])
		frame.fragNProcessed = true
	}
	// Check length of the reassembled packet.
	if l.buf.Len() != pktLen {
		log.Error("Packet len for reassembled packet does not match header",
			"expected", pktLen, "have", l.buf.Len())
	} else {
		// Write the packet to the wire.
		if err := send(l.buf.Bytes()); err != nil {
			log.Error("Unable to send reassembled packet", "err", err)
		}
	}
	// Process the complete packets in the last frame
	frame.ProcessCompletePkts()
	// Remove all processed frames from the list.
	l.removeProcessed()
}

func (l *ReassemblyList) removeEntry(e *list.Element) {
	frame := e.Value.(*FrameBuf)
	log.Debug("Removing frame from reassembly list", "epoch", l.epoch, "frame", frame.String())
	l.releaseFrame(frame)
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

func (l *ReassemblyList) releaseFrame(frame *FrameBuf) {
	frame.Reset()
	l.bufPool.Put(frame)
}

func min(x, y int) int {
	if x <= y {
		return x
	}
	return y
}
