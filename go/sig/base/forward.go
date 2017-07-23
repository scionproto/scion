package base

import (
	"io"
	"net"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
)

//   SIG Frame Header, used to encapsulate SIG to SIG traffic. The sequence
//   number is used to determine packet reordering and loss. The index is used
//   to determine where the first packet in the frame starts. The epoch is used
//   to handle sequence number resets, whether from a SIG restarting, or the
//   sequence number wrapping. The epoch values are the lowest 16b of the unix
//   timestamp at the reset point.
//
//      0B       1        2        3        4        5        6        7
//  +--------+--------+--------+--------+--------+--------+--------+--------+
//  |         Sequence number           |     Index       |      Epoch      |
//  +--------+--------+--------+--------+--------+--------+--------+--------+
//
const (
	SIGHdrSize          = 8
	PktLenSize          = 2
	MinSpace            = 16
	InternalIngressName = "scion.local"
)

var (
	InternalIngress io.ReadWriteCloser
	ExternalIngress *scion.SCIONConn
)

type BufferPool struct {
	pool *sync.Pool
}

func NewBufferPool() *BufferPool {
	new := func() interface{} {
		//log.Debug("Alloc'ing")
		return make([]byte, 64*1024)
	}
	bp := &BufferPool{
		pool: &sync.Pool{New: new},
	}
	for i := 0; i < 32; i++ {
		bp.Put(make([]byte, 64*1024))
	}
	return bp
}

func (bp *BufferPool) Get() []byte {
	// Reset slice to entire buffer
	b := bp.pool.Get().([]byte)
	return b[:cap(b)]
}

func (bp *BufferPool) Put(b []byte) {
	bp.pool.Put(b)
}

type EgressWorker struct {
	info *asInfo
	src  io.ReadWriteCloser
	c    chan common.RawBytes
	bp   *BufferPool

	epoch    uint16
	seq      uint32
	index    uint16
	frameOff int
}

const EgressChanSize = 128

func NewEgressWorker(info *asInfo) *EgressWorker {
	return &EgressWorker{
		info: info,
		src:  info.Device,
		c:    make(chan common.RawBytes, EgressChanSize),
		bp:   NewBufferPool(),
	}
}

func (e *EgressWorker) Run() error {
	// Start reader goroutine
	go e.Read()

	frame := make(common.RawBytes, 1<<16)
	var pkt common.RawBytes
	var conn net.Conn
	var err error
	e.frameOff = SIGHdrSize

TopLoop:
	for {
		if e.frameOff%8 != 0 {
			// Pad to multiple of 8B
			e.frameOff += 8 - (e.frameOff % 8)
		}
		// FIXME(kormat): there's no reason we need to run this for _every_ packet.
		// also, this should be dropping old packets to keep the buffer queue clear.
		conn, err = e.info.getConn()
		if err != nil {
			log.Error("Unable to get flow", "err", err)
			// No connection is available, back off for 500ms and try again
			<-time.After(500 * time.Millisecond)
			continue
		}
		// FIXME(kormat): calculate the max payload size based on path's MTU
		frame = frame[:1280]

		log.Debug("Top of loop", "frameOff", e.frameOff, "seqNumber", e.seq, "index", e.index)
		if e.frameOff == SIGHdrSize {
			// Don't have a partial frame, so block indefiniely for the next packet.
			pkt = <-e.c
			log.Debug("No partial frame, got new packet")
		} else {
			// Have partial frame
			select {
			case pkt = <-e.c:
				// Another packet was available, process it
				log.Debug("Have partial frame, got new packet")
			default:
				log.Debug("Have partial frame, no new packet, send partial frame",
					"frameOff", e.frameOff, "seqNumber", e.seq, "index", e.index)
				// No packets available, send existing frame.
				err := e.Write(conn, frame[:e.frameOff])
				if err != nil {
					log.Error("Error sending frame", "err", err)
				}
				e.bp.Put(pkt)
				continue TopLoop
			}
		}
		if err := e.CopyPkt(conn, frame, pkt); err != nil {
			log.Error("Error sending frame", "err", err)
		}
		e.bp.Put(pkt)
	}
}

func (e *EgressWorker) CopyPkt(conn net.Conn, frame, pkt common.RawBytes) error {
	if e.index == 0 {
		// This is the first start of a packet in this frame, so set the index
		e.index = uint16(e.frameOff / 8)
	}
	// Write packet length to frame
	common.Order.PutUint16(frame[e.frameOff:], uint16(len(pkt)))
	e.frameOff += PktLenSize
	pktOff := 0
	log.Debug("Starting to copy packet")
	// Write chunks of the packet to frames, sending off frames as they fill up.
	for {
		log.Debug("Copy packet top", "frameOff", e.frameOff, "pktOff", pktOff)
		copied := copy(frame[e.frameOff:], pkt[pktOff:])
		pktOff += copied
		e.frameOff += copied
		log.Debug("Copy packet middle", "frameOff", e.frameOff, "pktOff", pktOff, "copied", copied)
		if len(frame)-e.frameOff < MinSpace {
			// There's no point in trying to fit another packet into this frame.
			if err := e.Write(conn, frame[:e.frameOff]); err != nil {
				// Skip the rest of this packet.
				return err
			}
		}
		if pktOff == len(pkt) {
			// This packet is now finished, time to get a new one.
			break
		}
		// Otherwise continue copying packet into next frame.
	}

	return nil
}

func (e *EgressWorker) Read() {
	for {
		pktBuffer := e.bp.Get()
		bytesRead, err := e.src.Read(pktBuffer)
		if err != nil {
			log.Error("Egress read error", "err", err)
			return
		}
		e.c <- pktBuffer[:bytesRead]
	}
}

func (e *EgressWorker) Write(conn net.Conn, frame common.RawBytes) error {
	if e.seq == 0 {
		e.epoch = uint16(time.Now().Unix() & 0xFFFF)
	}
	log.Debug("EgressWorker.Write", "len", len(frame), "epoch", e.epoch,
		"seq", e.seq, "index", e.index)

	// Write SIG header
	common.Order.PutUint32(frame[:4], e.seq)
	common.Order.PutUint16(frame[4:6], e.index)
	common.Order.PutUint16(frame[6:8], e.epoch)
	// Update metadata
	e.seq += 1
	e.index = 0
	e.frameOff = SIGHdrSize
	// Send frame
	_, err := conn.Write(frame)
	if err != nil {
		return common.NewError("Egress write error", "err", err)
	}
	return nil
}

func send(packet []byte) error {
	_, err := InternalIngress.Write(packet)
	if err != nil {
		return common.NewError("Unable to write to Internal Ingress", "err", err,
			"length", len(packet))
	}
	return nil
}

func IngressWorker(scionNet *scion.SCIONNet, listenAddr addr.HostAddr, listenPort uint16) {
	// Buffer for reading from the SCION socket
	scionBuffer := make([]byte, 64*1024)
	// Buffer to reassemble IP packets
	packet := make([]byte, 64*1024)

	lastSequenceNumber := -1
	packetStart := 0
	packetLength := 0
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
ReceiveLoop:
	for {
		// Flag when current frame contains data belonging to a last packet in the previous frames
		discardContinuation := false
		read, err := ExternalIngress.Read(scionBuffer)
		//log.Debug("Read SCION packet", "size", read, "data", scionBuffer[:read])
		if err != nil {
			log.Error("IngressWorker: Unable to read from External Ingress", "err", err)
			continue
		}

		frame := scionBuffer[:read]
		sequenceNumber := int(common.Order.Uint32(frame[:4]))
		index := common.Order.Uint16(frame[4:6])
		// Reslice after the header to simplify parsing
		payload := frame[SIGHdrSize:]
		//log.Debug("Received frame", "length", len(frame))

		if sequenceNumber <= lastSequenceNumber {
			log.Warn("IngressWorker: Received out of order sequence number", "last", lastSequenceNumber, "now", sequenceNumber)
			continue
		}
		if sequenceNumber != lastSequenceNumber+1 {
			log.Warn("IngressWorker: Unexpected sequence number", "last", lastSequenceNumber, "now", sequenceNumber)
			// Lost a frame somewhere, discard contents of partially built packet
			log.Warn("IngressWorker: Unable to reassemble IP packet, discarding previously received bytes",
				"bytesDiscarded", packetStart)
			discardContinuation = true
		}

		// Index = 0 means no new packet starts in this frame
		if index == 0 {
			// Entire frame contains continuation data
			if discardContinuation {
				// The entire content of this frame is part of a packet that's missing pieces,
				// jump directly to the next frame
				log.Info("IngressWorker: Frame only contains garbage, discarding", "sequenceNumber", sequenceNumber)
				packetStart = 0
				continue
			}

			lastSequenceNumber = sequenceNumber
			if len(packet[packetStart:]) < len(payload) {
				log.Error("IngressWorker: Unable to fit oversized IP packet", "bufferLen", cap(packet),
					"packetSize", packetStart+len(payload))
				packetStart = 0
				continue
			}
			copy(packet[packetStart:], payload)
			packetStart += len(payload)

			// Does the packet end here?
			if packetStart == packetLength {
				err = send(packet[:packetStart])
				if err != nil {
					log.Error("IngressWorker: Unable to send reassembled packet", "err", err)
					packetStart = 0
				}
				continue
			}

			// Packet continues in the next frame, so jump to processing it
			continue
		}

		// We now know that new packets exist in this frame
		// Reindex in C style, starting from 0
		index -= 1
		lastSequenceNumber = sequenceNumber

		// If there is continuation data at the beginning of the frame,
		// we only copy it if we haven't lost the previous one
		if index != 0 && discardContinuation == false {
			// Start of frame contains continuation data
			if len(packet[packetStart:]) < len(payload[:index]) {
				log.Error("IngressWorker: Unable to fit oversize IP packet", "bufferLen", cap(packet),
					"packetSize", packetStart+len(payload[:index]))
				continue
			}
			copy(packet[packetStart:], payload[:index])
			packetStart += len(payload[:index])

			// Finished the packet
			err := send(packet[:packetStart])
			if err != nil {
				log.Error("IngressWorker: Unable to send reassembled IP packet", "err", err)
			}
		}

		// Loop to process remaining packets, reslice to beginning of first packet
		payload = payload[index:]
		packetStart = 0
		for {
			version := uint8(payload[0]) >> 4
			if version != 4 {
				log.Warn("Unsupported IP version", "version", version)
				// Rest of frame cannot be reliably parsed, jump to next one
				continue ReceiveLoop
			}

			// Version is correct, grab total length
			packetLength = int(common.Order.Uint16(payload[2:4]))
			//log.Debug("Found IP packet", "length", packetLength)
			if packetLength > 1500 {
				log.Warn("Found large IP packet", "length", packetLength)
			}

			if packetLength > len(payload) {
				// Need to reconstruct the full IP packet across frames
				copy(packet[packetStart:], payload)
				packetStart += len(payload)
				continue ReceiveLoop
			}

			if packetLength <= len(payload) {
				//log.Debug("Sending packet", "payload", payload, "len", len(payload))
				err := send(payload)
				if err != nil {
					log.Error("Unable to send IP packet", "packet", payload)
					continue ReceiveLoop
				}
				if packetLength == len(payload) {
					// The end of the IP packet is the end of the frame
					continue ReceiveLoop
				}
			}

			// This frame contains data after this packet, try to parse another one
			payload = payload[packetLength:]
		}
	}
}
