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
	FrameBufPoolCap    = 300
	// FrameBufCap is the size of a preallocated frame buffer.
	FrameBufCap        = 65535
	// MaxSeqNrDist is the maximum difference between arriving sequence numbers.
	MaxSeqNrDist       = 10
	// ReassemblyListCap is the maximum capacity of a reassembly list.
	ReassemblyListCap  = 100
	// CleanUpInterval is the interval between clean up of outdated reassembly lists.
	CleanUpInterval    = 1 * time.Second
)

// FrameBuf is a struct used to reassembly encapsulated packets spread over
// multiple SIG frames. It contains the raw bytes and metadata needed for reassembly.
type FrameBuf struct {
	seqNr          int
	index          int
	len            int
	endProcessed   bool
	hasStart       bool
	pktStart       int
	startProcessed bool
	pktLen         int
	raw            []byte
}

// Reset resets the metadata of a frame buffer.
func (fb *FrameBuf) Reset() {
	fb.seqNr = -1
	fb.index = -1
	fb.len = 0
	fb.endProcessed = false
	fb.hasStart = false
	fb.pktStart = 0
	fb.pktLen = 0
	fb.startProcessed = false
}

// Processed returns true if all fragments in the frame have been processed,
func (fb *FrameBuf) Processed() bool {
	return fb.endProcessed && (!fb.hasStart || fb.startProcessed)
}

func (fb *FrameBuf) String() string {
	return fmt.Sprintf("SeqNr: %d Index: %d Len: %d pktStart: %d",
		fb.seqNr, fb.index, fb.len, fb.pktStart)
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
		buf:               bytes.NewBuffer(make([]byte, 0, FrameBufCap)),
	}
	return list
}

// Insert inserts a frame into the reassembly list. In case the list has no capacity
// anymore the oldest frame (with regard to the sequence number) in the list gets evicted.
// After inserting the frame at the correct position, Insert tries to reassemble packets
// that involve the newly added frame. Completely processed frames get removed from the
// list and released to the pool of frame buffers.
func (l *ReassemblyList) Insert(frame *FrameBuf) {
	log.Debug("Adding frame to reassembly list", "epoch", l.epoch,"frame", frame.String())
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
		if frame.hasStart {
			l.tryReassemble(elem)
		}
		return
	}
	// Frame should be added somewhere in the middle or at the end of the list.
	// Check if we have capacity.
	if l.entries.Len() == l.capacity {
		l.removeOldest()
	}
	var lastStart *list.Element
	var insertedElem *list.Element
	if firstFrame.hasStart && !firstFrame.startProcessed {
		lastStart = first
	}
	for e := first.Next(); e != nil; e = e.Next() {
		entry := e.Value.(*FrameBuf)
		if frame.seqNr < entry.seqNr {
			// We have found the place to insert.
			insertedElem = l.entries.InsertBefore(frame, e)
			break
		}
		if entry.hasStart && !entry.startProcessed {
			lastStart = e
		}
	}
	if insertedElem == nil {
		// Add frame at end and try to reassemble from last known start of a packet.
		insertedElem = l.entries.PushBack(frame)
	}
	// Check if we can reassemble something.
	// Case 1: The current frame contains the end of a packet or connects multiple frames.
	l.tryReassemble(lastStart)
	// Case 2: The current frame contains the start of a packet.
	if frame.hasStart {
		l.tryReassemble(insertedElem)
	}
}

// tryReassemble tries to reassemble fragments starting at 'from'.
func (l *ReassemblyList) tryReassemble(from *list.Element) {
	if from == nil {
		return
	}
	fromFrame := from.Value.(*FrameBuf)
	if !fromFrame.hasStart {
		return
	}
	prevSeqNr := fromFrame.seqNr
	bytes := fromFrame.len - fromFrame.pktStart
	var to *list.Element
	for e := from.Next(); e != nil; e = e.Next() {
		currFrame := e.Value.(*FrameBuf)
		if currFrame.seqNr == prevSeqNr+1 {
			prevSeqNr = currFrame.seqNr
			// Add number of bytes contained in this frame.
			if currFrame.index == 0 {
				bytes += currFrame.len
			}
			// Check if we have found all frames.
			if fromFrame.pktLen-bytes <= currFrame.index*8 {
				to = e
				break
			}
		}
		// Missing frame. Cannot reassemble packet yet.
		break
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
	l.buf.Write(fromFrame.raw[fromFrame.pktStart:fromFrame.len])
	fromFrame.startProcessed = true
	// Collect rest.
	var next *list.Element
	for e := from.Next(); l.buf.Len() < fromFrame.pktLen && e != to.Next(); e = next {
		frame := e.Value.(*FrameBuf)
		missingBytes := pktLen - l.buf.Len()
		l.buf.Write(frame.raw[:min(missingBytes, frame.len)])
		frame.endProcessed = true
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
	send(l.buf.Bytes())
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
			raw: make([]byte, FrameBufCap),
		}
		buf.Reset()
		state.bufPool <- buf
	}
	return state
}

func (s *IngressState) getFrameBuf() *FrameBuf {
	buf := <-s.bufPool
	return buf
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
			// Release all frames to the frame pool and remove the reassembly list.
			log.Debug("Removing reassembly list", "epoch", epoch)
			rlist.removeAll()
			delete(s.reassemblyLists, epoch)
		} else {
			// Mark the reassembly list for deletion. If it is not accessed between now
			// and the next cleanup interval, it will be removed.
			rlist.markedForDeletion = true
		}
	}
}

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
	for {
		select {
		case <-time.Tick(CleanUpInterval):
			go state.cleanUp()
		default:
			frame := state.getFrameBuf()
			read, err := ExternalIngress.Read(frame.raw)
			if err != nil {
				log.Error("IngressWorker: Unable to read from External Ingress", "err", err)
				continue
			}
			frame.len = read
			if err := processFrame(frame, state); err != nil {
				log.Error("Error while processing frame", "err", err)
			}
		}
	}
}

// processFrame processes a SIG frame by first writing all completely contained
// packets to the wire and then adding the frame to the corresponding reassembly
// list if needed.
func processFrame(frame *FrameBuf, state *IngressState) error {
	seqNr := int(common.Order.Uint32(frame.raw[:4]))
	index := int(common.Order.Uint16(frame.raw[4:6]))
	epoch := int(common.Order.Uint16(frame.raw[6:8]))
	addToReassembly := false

	log.Debug("Received Frame", "seqNr", seqNr, "index", index, "epoch", epoch,
		"len", len(frame.raw))

	if index == 0 {
		// No new packets in this frame.
		log.Debug("No new packets in frame", "seqNr", seqNr)
		frame.hasStart = false
		// Add frame to frame buf list and check if we can reassemble a packet.
		addToReassembly = true
	} else {
		addToReassembly = processPkts(frame, 8*index)
		if index > 1 {
			// There is a fragment at the beginning of the frame.
			addToReassembly = true
		}
	}
	if addToReassembly {
		// Add to frame buf reassembly list.
		rlist := state.getReassemblyList(epoch)
		rlist.Insert(frame)
	}
	return nil
}

// Processes all packets in a frame and returns true if there is an incomplete
// packet at the end of the frame, otherwise false.
func processPkts(frame *FrameBuf, start int) bool {
	offset := start
	incompletePkt := false
	for offset < frame.len {
		pktLen := int(common.Order.Uint16(frame.raw[offset:offset+4]))
		offset += 4
		rawPkt := frame.raw[offset:frame.len]
		if len(rawPkt) <= pktLen {
			// We got everything, write it out to the wire without copying to pkt buf.
			log.Debug("ProcessPkt: directly write pkt", "seqNr", frame.seqNr, "len", pktLen)
			send(rawPkt[:pktLen])
			offset += pktLen
			// Packet always starts at 8-byte boundary.
			offset = pad(offset)
			continue
		}
		// There is an incomplete packet at the end of the frame.
		frame.hasStart = true
		frame.pktStart = offset
		frame.pktLen = pktLen
		incompletePkt = true
		break
	}
	return incompletePkt
}

func min(x, y int) int {
	if x <= y {
		return x
	}
	return y
}

func pad(x int) int {
	return x + (8 - (x%8))%8
}