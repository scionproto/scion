package base

import (
	"io"
	"net"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

//   SIG Frame Header, used to encapsulate SIG to SIG traffic. The sequence
//   number is used to determine packet reordering and loss. The index is used
//   to determine where the first packet in the frame starts.
//
//      0B       1        2        3        4        5        6        7
//  +--------+--------+--------+--------+--------+--------+--------+--------+
//  |         Sequence number           |     Index       |    Reserved     |
//  +--------+--------+--------+--------+--------+--------+--------+--------+
//
const (
	SIGHdrSize          = 8
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

// asyncReader continuously takes data from source and writes it to pc.
// Packet bounds are communicated through packetOffsets.
func tunnelReader(source io.ReadWriteCloser, bp *BufferPool, buffers chan<- []byte) {
	for {
		pktBuffer := bp.Get()
		bytesRead, err := source.Read(pktBuffer)
		if err != nil {
			log.Error("Egress read error", "err", err)
			return
		}
		//log.Debug("Wrote to channel", "len", bytesRead)
		buffers <- pktBuffer[:bytesRead]
	}
}

func incSeqNumber(seqNumber uint32) uint32 {
	return seqNumber + 1
}

func sendFrame(conn net.Conn, frame []byte, seqNumber *uint32, index int) error {
	// Encapsulate and flush
	common.Order.PutUint32(frame[:4], *seqNumber)
	*seqNumber = incSeqNumber(*seqNumber)
	common.Order.PutUint16(frame[4:6], uint16(index)+1)

	// NOTE(scrye): This _might_ block (although it means that the
	// outgoing OS-level socket is saturated with data, which we
	// cannot help anyway). Other than buffering more packets
	// (which for high speed links will not be a solution), there's
	// nothing we can do here.
	//log.Debug("Sent frame", "length", len(frame), "data", frame)
	_, err := conn.Write(frame)
	if err != nil {
		return common.NewError("Egress write error", "err", err)
	}
	return nil
}

type State int

const (
	NEW_FRAME State = iota
	COPY_PKT
	EMPTY_FRAME
	PARTIAL_FRAME
	SEND_FRAME
)

func EgressWorker(info *asInfo) {
	frameBuffer := make([]byte, 64*1024)
	var seqNumber uint32

	// Continuously read from tunnel interface, putting data into pc
	bp := NewBufferPool()
	buffers := make(chan []byte, 128)
	go tunnelReader(info.Device, bp, buffers)

	var frame, frameFreeSpace []byte
	var pkt, pktRemaining []byte
	var fillOffset int
	var index int
	var state State
	var flow net.Conn
	var err error
	for {
		switch state {
		case NEW_FRAME:
			//log.Debug("State", "state", "NEW_FRAME")
			flow, err = info.getConn()
			if err != nil {
				log.Error("Unable to get flow", "err", err)
				// No connection is available, back off for 500ms and try again
				<-time.After(500 * time.Millisecond)
				continue
			}
			// TODO bytesMaxToRead := flow.MTU
			bytesMaxToRead := 1280
			frame = frameBuffer[:SIGHdrSize+bytesMaxToRead]
			frameFreeSpace = frame[SIGHdrSize:]
			fillOffset = 0
			index = -1
			state = COPY_PKT
			if pkt == nil {
				state = EMPTY_FRAME
			} else {
				state = COPY_PKT
			}
		case PARTIAL_FRAME:
			// We already have some data, if there's no more data just flush
			//log.Debug("State", "state", "GET_PACKET")
			select {
			case pkt = <-buffers:
				//log.Debug("Got packet", "length", len(pkt))
				pktRemaining = pkt
				// If this is the first packet in the
				// frame, store the index
				if index == -1 {
					index = fillOffset
				}
				state = COPY_PKT
			default:
				//log.Debug("Flushing")
				state = SEND_FRAME
			}
		case EMPTY_FRAME:
			// We do not have data, block while waiting
			pkt = <-buffers
			//log.Debug("Got packet", "length", len(pkt))
			pktRemaining = pkt
			if index == -1 {
				index = fillOffset
			}
			state = COPY_PKT
		case COPY_PKT:
			//log.Debug("State", "state", "FILL_FRAME")
			bytesCopied := copy(frameFreeSpace, pktRemaining)
			frameFreeSpace = frameFreeSpace[bytesCopied:]
			fillOffset += bytesCopied
			if bytesCopied < len(pktRemaining) {
				// Not enough space for this packet in
				// this frame, continue in next frame
				pktRemaining = pktRemaining[bytesCopied:]
				state = SEND_FRAME
			} else {
				// Packet was fully copied, release buffer
				bp.Put(pkt)
				pkt = nil
				state = PARTIAL_FRAME
			}
		case SEND_FRAME:
			//log.Debug("State", "state", "SEND_FRAME")
			err = sendFrame(flow, frame[:fillOffset+SIGHdrSize], &seqNumber, index)
			if err != nil {
				log.Error("Unable to send frame", "len", fillOffset, "err", err)
			}
			state = NEW_FRAME
		}
	}
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
