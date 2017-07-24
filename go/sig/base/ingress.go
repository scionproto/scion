package base

import (
	"bytes"
	"container/list"
	"fmt"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

const (
	// FrameBufPoolCap is the number of preallocated frame buffers.
	FrameBufPoolCap = 300
	// FrameBufCap is the size of a preallocated frame buffer.
	FrameBufCap = 65535
	// MaxSeqNrDist is the maximum difference between arriving sequence numbers.
	MaxSeqNrDist = 10
	// ReassemblyListCap is the maximum capacity of a reassembly list.
	ReassemblyListCap = 100
	// CleanUpInterval is the interval between clean up of outdated reassembly lists.
	CleanUpInterval = 1 * time.Second
)

// IngressWorker handles decapsulation of SIG frames. There is one IngressWorker per
// remote SIG.
func IngressWorker(scionNet *scion.SCIONNet, listenAddr addr.HostAddr, listenPort uint16) {
	var err error
	ExternalIngress, err = scionNet.ListenSCION(listenAddr, listenPort)
	if err != nil {
		log.Error("Unable to initialize ExternalIngress", "err", err)
		return
	}
	InternalIngress, err = xnet.ConnectTun(InternalIngressName)
	if err != nil {
		log.Error("Unable to connect to InternalIngress", "err", err)
		return
	}
	state := NewIngressState()
	cleanupTimer := time.Tick(CleanUpInterval)
	for {
		select {
		case <-cleanupTimer:
			state.cleanUp()
		default:
			frame := state.getFrameBuf()
			read, err := ExternalIngress.Read(frame.raw)
			if err != nil {
				log.Error("IngressWorker: Unable to read from External Ingress", "err", err)
				// Release Frame
				frame.Reset()
				state.bufPool <- frame
				continue
			}
			frame.frameLen = read
			processFrame(frame, state)
		}
	}
}

// FrameBuf is a struct used to reassemble encapsulated packets spread over
// multiple SIG frames. It contains the raw bytes and metadata needed for reassembly.
type FrameBuf struct {
	// Sequence number of the frame.
	seqNr int
	// Index of the frame.
	index int
	// Total length of the frame (including 8-byte header).
	frameLen int
	// Start of the fragment that starts a new packet. 0 means that there
	// is no such fragment. This points to the start of the header of the packet,
	// i.e., the 2-byte packet len preceding the packet header is not included.
	frag0Start int
	// Whether fragment 0 has been processed already when reassembling.
	frag0Processed bool
	// Whether fragment N has been processed already when reassembling. Fragment N
	// denotes the fragment that completes a packet. Note that with the way packets
	// are in encapsulated, such a fragment will always be at the start of a frame
	// (if there is one).
	fragNProcessed bool
	// The packet len of the packet that starts at fragment0. Has no meaning
	// if there is no such fragment.
	pktLen int
	// The raw bytes buffer for the frame.
	raw common.RawBytes
}

// Reset resets the metadata of a frame buffer.
func (fb *FrameBuf) Reset() {
	fb.seqNr = -1
	fb.index = -1
	fb.frameLen = 0
	fb.frag0Start = 0
	fb.frag0Processed = false
	fb.fragNProcessed = false
	fb.pktLen = 0
}

// Processed returns true if all fragments in the frame have been processed,
func (fb *FrameBuf) Processed() bool {
	return fb.fragNProcessed && (fb.frag0Start == 0 || fb.frag0Processed)
}

func (fb *FrameBuf) String() string {
	return fmt.Sprintf("SeqNr: %d Index: %d Len: %d frag0Start: %d processed: (%t, %t)",
		fb.seqNr, fb.index, fb.frameLen, fb.frag0Start, fb.fragNProcessed, fb.frag0Processed)
}

// IngressState contains the state needed by an ingress worker.
type IngressState struct {
	bufPool         chan *FrameBuf
	reassemblyLists map[int]*ReassemblyList
}

func NewIngressState() *IngressState {
	state := &IngressState{
		bufPool:         make(chan *FrameBuf, FrameBufPoolCap),
		reassemblyLists: make(map[int]*ReassemblyList),
	}
	for i := 0; i < FrameBufPoolCap; i++ {
		buf := &FrameBuf{
			raw: make(common.RawBytes, FrameBufCap),
		}
		buf.Reset()
		state.bufPool <- buf
	}
	return state
}

func (s *IngressState) getFrameBuf() *FrameBuf {
	return <-s.bufPool
}

func (s *IngressState) getReassemblyList(epoch int) *ReassemblyList {
	rlist, ok := s.reassemblyLists[epoch]
	if !ok {
		rlist = NewReassemblyList(epoch, ReassemblyListCap, s.bufPool)
		s.reassemblyLists[epoch] = rlist
	}
	rlist.markedForDeletion = false
	return rlist
}

func (s *IngressState) cleanUp() {
	for epoch, rlist := range s.reassemblyLists {
		if rlist.markedForDeletion {
			// Reassembly list has been marked for deletion in a previous cleanup run.
			// Remove the reassembly list from the map and then release all frames
			// back to the bufpool.
			log.Debug("Removing reassembly list", "epoch", epoch)
			delete(s.reassemblyLists, epoch)
			go rlist.removeAll()
		} else {
			// Mark the reassembly list for deletion. If it is not accessed between now
			// and the next cleanup interval, it will be removed.
			rlist.markedForDeletion = true
		}
	}
}

// processFrame processes a SIG frame by first writing all completely contained
// packets to the wire and then adding the frame to the corresponding reassembly
// list if needed.
func processFrame(frame *FrameBuf, state *IngressState) {
	seqNr := int(common.Order.Uint32(frame.raw[:4]))
	index := int(common.Order.Uint16(frame.raw[4:6]))
	epoch := int(common.Order.Uint16(frame.raw[6:8]))
	addToReassembly := false

	frame.seqNr = seqNr
	frame.index = index
	log.Debug("Received Frame", "seqNr", seqNr, "index", index, "epoch", epoch,
		"len", frame.frameLen)

	if index == 0 {
		// No new packets in this frame.
		log.Debug("No new packets in frame", "seqNr", seqNr)
		// Add frame to frame buf list and check if we can reassemble a packet.
		addToReassembly = true
	} else {
		addToReassembly = processPkts(frame, 8*index)
		if index > 1 {
			// There is a fragment at the beginning of the frame.
			addToReassembly = true
		}
	}
	// If index == 1 then we can be sure that there is no fragment at the beginning
	// of the frame.
	frame.fragNProcessed = index == 1
	if addToReassembly {
		// Add to frame buf reassembly list.
		rlist := state.getReassemblyList(epoch)
		rlist.Insert(frame)
	} else {
		// The frame is already completely processed. Release it.
		frame.Reset()
		state.bufPool <- frame
	}
}

// Processes all packets in a frame and returns true if there is an incomplete
// packet at the end of the frame, otherwise false.
func processPkts(frame *FrameBuf, start int) bool {
	offset := start
	var pktLen int
	for offset < frame.frameLen {
		pktLen = int(common.Order.Uint16(frame.raw[offset : offset+2]))
		offset += 2
		rawPkt := frame.raw[offset:frame.frameLen]
		if len(rawPkt) < pktLen {
			break
		}
		// We got everything, write it out to the wire without copying to pkt buf.
		log.Debug("ProcessPkt: directly write pkt", "seqNr", frame.seqNr, "len", pktLen)
		send(rawPkt[:pktLen])
		offset += pktLen
		// Packet always starts at 8-byte boundary.
		offset = pad(offset)
	}
	if offset < frame.frameLen {
		// There is an incomplete packet at the end of the frame.
		frame.frag0Start = offset
		frame.pktLen = pktLen
		return true
	}
	return false
}

// ReassemblyList is used to keep a doubly linked list of SIG frames that are
// outstanding for reassembly. The frames kept in the reassambly list sorted by
// their sequence numbers. There is always one reassembly list per epoch to
// ensure that sequence numbers are monotonically increasing.
type ReassemblyList struct {
	epoch             int
	capacity          int
	bufPool           chan *FrameBuf
	markedForDeletion bool
	entries           *list.List
	buf               *bytes.Buffer
}

// NewReassemblyList returns a ReassemblyList object for the given epoch, with given
// maximum capacity and using bufPool to release processed frame buffers into.
func NewReassemblyList(epoch int, capacity int, bufPool chan *FrameBuf) *ReassemblyList {
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

// Insert inserts a frame into the reassembly list. In case the list has no capacity
// anymore the oldest frame (with regard to the sequence number) in the list gets evicted.
// After inserting the frame at the correct position, Insert tries to reassemble packets
// that involve the newly added frame. Completely processed frames get removed from the
// list and released to the pool of frame buffers.
func (l *ReassemblyList) Insert(frame *FrameBuf) {
	log.Debug("Adding frame to reassembly list", "epoch", l.epoch, "frame", frame.String())
	// If this is the first frame, just add it.
	if l.entries.Len() == 0 {
		l.entries.PushBack(frame)
		return
	}
	first := l.entries.Front()
	firstFrame := first.Value.(*FrameBuf)
	if frame.seqNr < firstFrame.seqNr {
		// This frame has the lowest seqNr in this epoch.
		// If there is no capacity or if the frame is too old, don't bother adding it.
		if l.entries.Len() == l.capacity || frame.seqNr < firstFrame.seqNr-MaxSeqNrDist {
			log.Debug("Discarding frame: too old", "epoch", l.epoch, "seqNr", frame.seqNr,
				"currentOldest", firstFrame.seqNr)
			l.releaseFrame(frame)
			return
		}
		// Add entry and check for reassembly.
		elem := l.entries.PushFront(frame)
		if frame.frag0Start != 0 {
			l.tryReassemble(elem)
		}
		return
	}
	// Frame should be added somewhere in the middle or at the end of the list.
	// Check if we have capacity.
	if l.entries.Len() == l.capacity {
		log.Debug("Reassembly list reached maximum capacity", "epoch", l.epoch, "cap", l.capacity)
		l.removeOldest()
	}
	var lastStart *list.Element
	var insertedElem *list.Element
	if firstFrame.frag0Start != 0 && !firstFrame.frag0Processed {
		lastStart = first
	}
	for e := first.Next(); e != nil; e = e.Next() {
		entry := e.Value.(*FrameBuf)
		if frame.seqNr < entry.seqNr {
			// We have found the place to insert.
			insertedElem = l.entries.InsertBefore(frame, e)
			break
		}
		if entry.frag0Start != 0 && !entry.frag0Processed {
			lastStart = e
		}
	}
	if insertedElem == nil {
		// Add frame at end and try to reassemble from last known start of a packet.
		insertedElem = l.entries.PushBack(frame)
	}
	// Check if we can reassemble something.
	// Case 1: The current frame contains the end of a packet or connects multiple frames.
	if frame.index != 1 {
		l.tryReassemble(lastStart)
	}
	// Case 2: The current frame contains the start of a packet.
	if frame.frag0Start != 0 {
		l.tryReassemble(insertedElem)
	}
}

// tryReassemble tries to reassemble fragments starting at 'from'.
func (l *ReassemblyList) tryReassemble(from *list.Element) {
	if from == nil {
		return
	}
	fromFrame := from.Value.(*FrameBuf)
	if fromFrame.frag0Start == 0 {
		return
	}
	prevSeqNr := fromFrame.seqNr
	bytes := fromFrame.frameLen - fromFrame.frag0Start
	var to *list.Element
	for e := from.Next(); e != nil; e = e.Next() {
		currFrame := e.Value.(*FrameBuf)
		if currFrame.seqNr != prevSeqNr+1 {
			// Missing frame. Cannot reassemble packet yet.
			break
		}
		prevSeqNr = currFrame.seqNr
		// Add number of bytes contained in this frame. This potentially adds
		// too much, but we are only using it to detect whether we potentially
		// have everything we need.
		bytes += (currFrame.frameLen - 8)
		// Check if we have found all frames.
		if bytes >= fromFrame.pktLen {
			to = e
			break
		}
		if currFrame.index != 0 {
			log.Error("Framing error occurred. Not enough bytes to reassemble packet",
				"startFrame", fromFrame.String(), "currFrame", currFrame.String())
			// TODO(shitz): We can potentially throw aways fromFrame and all frames
			// leading up to the current one.
			break
		}
	}
	if to != nil {
		l.collectAndWrite(from, to)
	}
}

// collectAndWrite collects all fragments of a reassembled packet starting in 'from'
// and ending in 'to' and writes the reassembled packet to the wire. Completely
// processed frames are removed from the reassembly list and returned to the frame
// buffer pool.
func (l *ReassemblyList) collectAndWrite(from *list.Element, to *list.Element) {
	if from == nil || to == nil {
		return
	}
	fromFrame := from.Value.(*FrameBuf)
	toFrame := to.Value.(*FrameBuf)
	log.Debug("Reassembling packet. Collecting buffers", "from", fromFrame.seqNr,
		"to", toFrame.seqNr)
	// Reset reassembly buffer.
	l.buf.Reset()
	// Collect the start of the packet.
	pktLen := fromFrame.pktLen
	l.buf.Write(fromFrame.raw[fromFrame.frag0Start:fromFrame.frameLen])
	fromFrame.frag0Processed = true
	// Collect rest.
	var next *list.Element
	for e := from.Next(); l.buf.Len() < pktLen && e != to.Next(); e = next {
		frame := e.Value.(*FrameBuf)
		missingBytes := pktLen - l.buf.Len()
		l.buf.Write(frame.raw[SIGHdrSize:min(missingBytes+SIGHdrSize, frame.frameLen)])
		frame.fragNProcessed = true
		next = e.Next()
		// Remove frame if it has been fully processed.
		if frame.Processed() {
			l.removeEntry(e)
		}
	}
	// Remove fromFrame if it has been fully processed.
	if fromFrame.Processed() {
		l.removeEntry(from)
	}
	// Check length of the reassembled packet.
	if l.buf.Len() != pktLen {
		log.Error("Packet len for reassembled packet does not match header",
			"expected", pktLen, "have", l.buf.Len())
		return
	}
	// Write the packet to the wire.
	if err := send(l.buf.Bytes()); err != nil {
		log.Error("Unable to send reassembled packet", "err", err)
	}
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

func (l *ReassemblyList) removeAll() {
	var next *list.Element
	for e := l.entries.Front(); e != nil; e = next {
		next = e.Next()
		l.removeEntry(e)
	}
}

func (l *ReassemblyList) releaseFrame(frame *FrameBuf) {
	frame.Reset()
	l.bufPool <- frame
}

func min(x, y int) int {
	if x <= y {
		return x
	}
	return y
}

func pad(x int) int {
	return x + (8-(x%8))%8
}
