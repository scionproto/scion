package base

import (
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
)

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

func NewFrameBuf() *FrameBuf {
	buf := &FrameBuf{raw: make(common.RawBytes, FrameBufCap)}
	buf.Reset()
	return buf
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
		//log.Debug("ProcessCompletePkts: directly write pkt", "seqNr", fb.seqNr,
		//	"offset", offset, "len", pktLen)
		if err := send(rawPkt[:pktLen]); err != nil {
			log.Error("Unable to send packet", "err", err)
		}
		offset += pktLen
		// Packet always starts at 8-byte boundary.
		offset = pad(offset)
	}
	if offset < fb.frameLen {
		// There is an incomplete packet at the end of the frame.
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

func pad(x int) int {
	return x + (8-(x%8))%8
}
