package base

import (
	"io"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/glycerine/rbuf"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/global"
)

const (
	SIGHdrSize = 8
)

// PC contains a classic condition-based Producer/Consumer ringbuffer. Readers
// take all the data they can. If there is no data available, they block
// indefinitely. Writers write all the data they can. If there is no space
// available, they block indefinitely. Blocked readers and writers are
// unblocked as soon as data or space becomes available.
type PC struct {
	ring          *rbuf.FixedSizeRingBuf
	mutex         sync.Mutex
	writePossible sync.Cond
	readPossible  sync.Cond
}

func NewPC(capacity int) *PC {
	pc := &PC{}
	pc.writePossible = *sync.NewCond(&pc.mutex)
	pc.readPossible = *sync.NewCond(&pc.mutex)
	pc.ring = rbuf.NewFixedSizeRingBuf(capacity)
	return pc
}

type offset struct {
	start int
	end   int
}

func min(x int, y int) int {
	if x < y {
		return x
	} else {
		return y
	}
}

// asyncReader continuously takes data from source and writes it to pc.
// Packet bounds are communicated through packetOffsets.
func asyncReader(source io.ReadWriteCloser, pc *PC, packetOffsets chan<- offset) {
	packet := make([]byte, 1500)
	counter := 0
	// TODO(scrye): this will break on int overflow, luckily Go panics anyway
	for {
		bytesRead, err := source.Read(packet)
		if err != nil {
			log.Error("Egress read error", "err", err)
			return
		}
		packetOffsets <- offset{start: counter, end: counter + bytesRead}
		counter += bytesRead

		bytesToWrite := bytesRead
		bytesWritten := 0
		for bytesToWrite > 0 {
			// Condition variable critical region start
			pc.mutex.Lock()
			for pc.ring.N-pc.ring.Readable <= 0 {
				pc.writePossible.Wait()
			}
			writeCapacity := pc.ring.N - pc.ring.Readable
			writeSize := min(writeCapacity, bytesToWrite)
			bytesNow, err := pc.ring.Write(packet[bytesWritten : bytesWritten+writeSize])
			pc.readPossible.Signal()
			pc.mutex.Unlock()
			// Condition variable critical region end

			if err != nil {
				log.Info("RingBuffer write error", "err", err, "bytesNow", bytesNow)
				continue
			}
			bytesToWrite -= bytesNow
			bytesWritten += bytesNow
		}
	}
}

func EgressWorker(info *asInfo) {
	packet := make([]byte, 1500)
	packetStartOffsets := make(chan offset, 256)
	pc := NewPC(512 * 1024)
	counter := 0
	seqNumber := uint32(0)
	lastOffset := offset{start: -1, end: -1}

	// Continuously read from tunnel interface, putting data into pc
	go asyncReader(info.Device, pc, packetStartOffsets)

	// Continuously get data from pc, putting it on the wire
	for {
		// Get a SCIONConn connection object to the destination
		flow, err := info.getConn()
		if err != nil {
			log.Error("Unable to get flow", "err", err)
			// No connection is available, back off for 500ms and try again
			<-time.After(500 * time.Millisecond)
			continue
		}

		// (say no to Nagle)
		// Read until there's nothing available or we have enough data for a packet
		// FIXME(scrye): compute correct MTU based on information in flow object
		// bytesMaxToRead := flow.MTU
		bytesMaxToRead := 1280
		bytesRead := 0

		// flushable signals that we have some data that we can push to the wire, we
		// do not need to wait for more
		flushable := false
	ReadLoop:
		for bytesMaxToRead > 0 {
			// Condition variable critical region start
			pc.mutex.Lock()
			for pc.ring.Readable == 0 {
				if flushable {
					// We have some data and are unwilling to wait for more
					pc.mutex.Unlock()
					break ReadLoop
				}
				pc.readPossible.Wait()
			}
			readSize := min(pc.ring.Readable, bytesMaxToRead)
			bytesNow, err := pc.ring.Read(packet[SIGHdrSize+bytesRead : SIGHdrSize+bytesRead+readSize])
			pc.writePossible.Signal()
			pc.mutex.Unlock()
			// Condition variable critical region end

			if err != nil {
				log.Info("RingBuffer read error", "err", err, "bytesNow", bytesNow)
				panic("RingBuffer read error")
			}
			bytesRead += bytesNow
			bytesMaxToRead -= bytesNow
			flushable = true
		}

		// Encapsulate and flush
		common.Order.PutUint32(packet[:4], seqNumber)
		seqNumber += 1

		startOffset := lastOffset
		nonZeroIndex := false
		// Read all offsets that end before the current frame
		for lastOffset.end < counter+bytesRead {
			// Grab a new offset, this will never block
			lastOffset = <-packetStartOffsets
			if lastOffset.start >= counter {
				// We found the first packet in the current frame, this will be our index
				startOffset = lastOffset
				nonZeroIndex = true
				break
			}
		}
		if nonZeroIndex {
			// Numbering in SIG-SIG frames starts at 1
			common.Order.PutUint16(packet[4:6], uint16(startOffset.start-counter)+1)
		} else {
			common.Order.PutUint16(packet[4:6], 0)
		}
		counter += bytesRead
		// NOTE(scrye): This _might_ block (although it means that the
		// outgoing OS-level socket is saturated with data, which we
		// cannot help anyway). Other than buffering more packets
		// (which for high speed links will not be a solution), there's
		// nothing we can do here.
		flow.Write(packet[:SIGHdrSize+bytesRead])
		if err != nil {
			log.Error("Egress write error", "err", err)
			return
		}
	}
}

func send(packet []byte) error {
	_, err := global.InternalIngress.Write(packet)
	if err != nil {
		log.Error("Unable to write to Internal Ingress", "err", err,
			"length", len(packet))
		return err
	}
	return nil
}

func IngressWorker() {
	// Buffer for reading from the SCION socket
	scionBuffer := make([]byte, 1500)
	// Buffer to reassemble IP packets
	packet := make([]byte, 3000)

	lastSequenceNumber := -1
	packetStart := 0
	packetLength := 0
ReceiveLoop:
	for {
		// Flag when current frame contains data belonging to a last packet in the previous frames
		discardContinuation := false
		read, err := global.ExternalIngress.Read(scionBuffer)
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
		//log.Debug("Frame payload", "payload", payload)

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

			if packetLength == len(payload) {
				// The end of the IP packet is the end of the frame
				//log.Debug("Sending packet", "payload", payload, "len", len(payload))
				err := send(payload)
				if err != nil {
					log.Error("Unable to send IP packet", "packet", payload)
					continue ReceiveLoop
				}
				continue ReceiveLoop
			}

			// This frame contains data after this packet, try to parse another one
			payload = payload[packetLength:]
		}
	}
}
