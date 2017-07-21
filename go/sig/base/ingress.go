package base

import (
	"fmt"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/global"
)

const (
	PktQueueCap = 10
	PktBufCap   = 65535
)

type PktBuf struct {
	raw        []byte
	len        int
	offset     int
	startSeqNr int
	nextSeqNr  int
	finished   bool
}

func NewPktBuf() *PktBuf {
	buf := &PktBuf{
		raw:        make([]byte, PktBufCap),
		len:        0,
		offset:     0,
		startSeqNr: -1,
		nextSeqNr:  -1,
		finished:   true,
	}
	return buf
}

func (b *PktBuf) Reset() {
	b.len = 0
	b.offset = 0
	b.startSeqNr = -1
	b.nextSeqNr = -1
	b.finished = false
}

func (b *PktBuf) String() string {
	return fmt.Sprintf("len: %d offset: %d startSeqNr: %d nextSeqNr: %d finished: %t",
		b.len, b.offset, b.startSeqNr, b.nextSeqNr, b.finished)
}

func (b *PktBuf) AddFragment(fragment []byte) error {
	if b.offset+len(fragment) > len(b.raw) {
		return common.NewError("Not enough space in PktBuf for fragment.",
			"spaceLeft", len(b.raw)-b.offset, "fragment len", len(fragment))
	}
	copy(b.raw[b.offset:], fragment)
	b.offset += len(fragment)
	log.Debug("Fragment added to pkt", "buf", b.String())
	return nil
}

func (b *PktBuf) Write() error {
	b.finished = true
	return send(b.raw[:b.len])
}

type PktQueue struct {
	bufs     []*PktBuf
	next     int
	capacity int
}

func NewPktQueue(capacity int) *PktQueue {
	queue = &PktQueue{next: 0, capacity: capacity}
	queue.bufs = make([]*PktBuf, capacity)
	for i := 0; i < capacity; i++ {
		queue.bufs[i] = NewPktBuf()
	}
	return queue
}

func (q *PktQueue) getPktBuf() *PktBuf {
	buf := q.bufs[q.next]
	if !buf.finished {
		log.Debug("Could not reassemble packet.", "seqNr", buf.startSeqNr)
	}
	buf.Reset()
	q.next++
	if q.next >= q.capacity {
		q.next = 0
	}
	return buf
}

var queue *PktQueue

func init() {
	queue = NewPktQueue(PktQueueCap)
}

func IngressWorker() {
	inputBuf := make([]byte, PktBufCap)
	for {
		read, err := global.ExternalIngress.Read(inputBuf)
		if err != nil {
			log.Error("IngressWorker: Unable to read from External Ingress", "err", err)
			continue
		}
		if err := processFrame(inputBuf[:read]); err != nil {
			log.Error("Error while processing frame", "err", err)
		}
	}
}

func processFrame(frame []byte) error {
	seqNr := int(common.Order.Uint32(frame[:4]))
	index := int(common.Order.Uint16(frame[4:6]))
	pld := frame[8:]
	pldLen := len(pld)
	offset := 0

	log.Debug("Received Frame", "seqNr", seqNr, "index", index, "pldLen", pldLen)

	for offset < pldLen {
		processedBytes := 0
		var err error
		switch index {
		case 0:
			// No new packets in this frame.
			log.Debug("No new packets in frame", "seqNr", seqNr)
			processedBytes, err = processFragment(pld, seqNr)
		case 1, -1:
			// New packet starts at the beginning of the frame or we already processed
			// the fragment at the beginning of the frame.
			log.Debug("Found new packet", "seqNr", seqNr, "offset", offset)
			processedBytes, err = processPkt(pld[offset:], seqNr)
		default:
			// There is a fragment from a previous packet and a new packet starting at index.
			log.Debug("Processing fragment at start of frame", "segNr", seqNr)
			processedBytes, err = processFragment(pld[:index], seqNr)
			// Set index to -1 to indicate that we already processed the fragment.
			index = -1
		}
		offset += processedBytes
		if err != nil {
			return err
		}
	}
	return nil
}

func processPkt(raw []byte, seqNr int) (int, error) {
	//version := uint8(raw[0]) >> 4
	pktLen := int(common.Order.Uint16(raw[2:4]))
	if len(raw) <= pktLen {
		// We got everything, write it out to the wire without copying to pkt buf.
		err := send(raw[:pktLen])
		log.Debug("ProcessPkt: directly write pkt", "len", pktLen)
		return pktLen, err
	}
	// Fragmented packet. Add to outstanding packets.
	pktBuf := queue.getPktBuf()
	pktBuf.len = pktLen
	pktBuf.startSeqNr = seqNr
	pktBuf.nextSeqNr = seqNr + 1
	err := pktBuf.AddFragment(raw[:pktLen])
	return min(pktLen, len(raw)), err
}

func processFragment(raw []byte, seqNr int) (int, error) {
	// Check if there is an outstanding packet for this fragment.
	for _, buf := range queue.bufs {
		if buf.nextSeqNr == seqNr && !buf.finished {
			buf.AddFragment(raw)
			if buf.offset == buf.len {
				// We got all the fragments. Write to wire.
				log.Debug("Reassembled pkt", "buf", buf.String())
				err := buf.Write()
				return len(raw), err
			}
			break
		}
	}
	log.Debug("Received fragment for unknown packet", "seqNr", seqNr)
	return len(raw), nil
}

func send(packet []byte) error {
	_, err := global.InternalIngress.Write(packet)
	if err != nil {
		return common.NewError("Unable to write to Internal Ingress", "err", err,
			"length", len(packet))
	}
	return nil
}
