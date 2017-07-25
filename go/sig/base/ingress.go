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
	// Whether all packets completely contained in the frame have been processed.
	completePktsProcessed bool
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
	fb.completePktsProcessed = false
	fb.pktLen = 0
}

// ProcessCompletePkts write all complete packets in the frame to the wire and
// sets the correct metadata in case there is a fragment at the end of the frame.
func (fb *FrameBuf) ProcessCompletePkts() {
	if fb.completePktsProcessed || fb.index == 0 {
		fb.completePktsProcessed = true
		return
	}
	offset := fb.index * 8
	var pktLen int
	for offset < fb.frameLen {
		pktLen = int(common.Order.Uint16(fb.raw[offset : offset+2]))
		offset += 2
		rawPkt := fb.raw[offset:fb.frameLen]
		if len(rawPkt) < pktLen {
			break
		}
		// We got everything for the packet. Write it out to the wire.
		log.Debug("ProcessCompletePkts: directly write pkt", "seqNr", fb.seqNr,
			"offset", offset, "len", pktLen)
		if err := send(rawPkt[:pktLen]); err != nil {
			log.Error("Unable to send packet", "err", err)
		}
		offset += pktLen
		// Packet always starts at 8-byte boundary.
		offset = pad(offset)
	}
	if offset < fb.frameLen {
		// There is an incomplete packet at the end of the frame.
		log.Debug("Found packet fragment at the end of frame", "seqNr", fb.seqNr,
			"start", offset, "pktLen", pktLen)
		fb.frag0Start = offset
		fb.pktLen = pktLen
	}
	fb.completePktsProcessed = true
	fb.frag0Processed = fb.frag0Start == 0
}

// Processed returns true if all fragments in the frame have been processed,
func (fb *FrameBuf) Processed() bool {
	return (fb.completePktsProcessed && fb.fragNProcessed &&
		(fb.frag0Start == 0 || fb.frag0Processed))
}

// SetProcessed marks a frame as being processed.
func (fb *FrameBuf) SetProcessed() {
	fb.completePktsProcessed = true
	fb.fragNProcessed = true
	fb.frag0Processed = true
}

func (fb *FrameBuf) String() string {
	return fmt.Sprintf("SeqNr: %d Index: %d Len: %d frag0Start: %d processed: (%t, %t, %t)",
		fb.seqNr, fb.index, fb.frameLen, fb.frag0Start, fb.fragNProcessed, fb.frag0Processed,
		fb.completePktsProcessed)
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
	log.Debug("GetFrameBuf", "poolSize", len(s.bufPool))
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
	frame.seqNr = seqNr
	frame.index = index
	log.Debug("Received Frame", "seqNr", seqNr, "index", index, "epoch", epoch,
		"len", frame.frameLen)
	// If index == 1 then we can be sure that there is no fragment at the beginning
	// of the frame.
	frame.fragNProcessed = index == 1
	// If index == 0 then we can be sure that there are no complete packets in this
	// frame.
	frame.completePktsProcessed = index == 0
	// Add to frame buf reassembly list.
	rlist := state.getReassemblyList(epoch)
	rlist.Insert(frame)
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
		l.releaseFrame(frame)
		return
	}
	last := l.entries.Back()
	lastFrame := last.Value.(*FrameBuf)
	// If there is a gap between this frame and the last in the reassembly list,
	// remove all packets from the reassembly list and only add this frame.
	if frame.seqNr != lastFrame.seqNr+1 {
		log.Info(fmt.Sprintf("Received frame out-of-order. Discarding %d frames.", l.entries.Len()),
			"epoch", l.epoch, "segNr", frame.seqNr, "currentNewest", lastFrame.seqNr)
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
