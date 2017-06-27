package base

import (
	"io"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/glycerine/rbuf"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/conn/scion"
	"github.com/netsec-ethz/scion/go/sig/defines"
)

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

type Offset struct {
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

func asyncBlockingEater(source io.ReadWriteCloser, pc *PC, packetStartOffsets chan<- Offset) {
	packet := make([]byte, 1500)
	counter := 0

	log.Debug("Starting asyncBlockingEater")
	// TODO(scrye): this will break on int overflow, luckily Go panics anyway
	for {
		bytesRead, err := source.Read(packet)
		if err != nil {
			log.Error("Egress read error", "err", err)
			return
		}
		packetStartOffsets <- Offset{start: counter, end: counter + bytesRead}
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
			log.Debug("Writing to ringbuffer", "size", writeSize, "capacity", writeCapacity)
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
	log.Debug("Started egress worker", "AS", info.Name)
	packetStartOffsets := make(chan Offset, 256)
	pc := NewPC(512 * 1024)
	counter := 0
	seqNumber := uint32(0)
	lastOffset := Offset{start: -1, end: -1}

	go asyncBlockingEater(info.Device, pc, packetStartOffsets)

	for {
		flow, err := info.getConn()
		if err != nil {
			log.Error("Unable to get flow", "err", err)
			<-time.After(500 * time.Millisecond)
			continue
		}

		// (say no to Nagle)
		// Read until there's nothing available or we have enough data for a packet
		// FIXME(scrye)
		// bytesMaxToRead := flow.MTU
		bytesMaxToRead := 900
		bytesRead := 0
		flushable := false
		log.Debug("EgressWorker", "MTU", flow.MTU)
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
			log.Debug("Reading from ringbuffer", "size", readSize, "available", pc.ring.Readable)
			bytesNow, err := pc.ring.Read(packet[8+bytesRead : 8+bytesRead+readSize])
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

		flow.Conn.Write(packet[:8+bytesRead])
		if err != nil {
			log.Error("Egress write error", "err", err)
			return
		}
	}
}

func send(global *defines.Global, packet []byte) error {
	_, err := global.InternalIngress.Write(packet)
	if err != nil {
		log.Error("Unable to write to Internal Ingress", "err", err,
			"length", len(packet))
		return err
	}
	return nil
}

func IngressWorker(global *defines.Global) {
	log.Debug("Started ingress worker", "AS", global.IA)
	scionBuffer := make([]byte, 1500)
	packet := make([]byte, 3000)

	lastSequenceNumber := -1
	packetStart := 0
	reassembledLength := 0

ReceiveLoop:
	for {
		discardContinuation := false
		log.Debug("Waiting for packets...")
		read, err := global.ExternalIngress.Read(scionBuffer)
		//log.Debug("Read SCION packet", "size", read, "data", scionBuffer[:read])
		if err != nil {
			log.Error("IngressWorker: Unable to read from External Ingress", "err", err)
			continue
		}

		_, frame, err := scion.ParseSCIONPacket(scionBuffer[:read])
		if err != nil {
			log.Error("IngressWorker: Unable to parse SCION packet", "packet", scionBuffer[:read], "error", err)
			continue
		}
		//log.Debug("SCION payload", "frame", frame)

		sequenceNumber := int(common.Order.Uint32(frame[:4]))
		index := common.Order.Uint16(frame[4:6])
		log.Debug("IngressWorker: SIG frame data", "sequenceNumber", sequenceNumber, "index", index)

		// Reslice after the header to simplify parsing
		payload := frame[8:]
		//log.Debug("Frame payload", "payload", payload)

		if sequenceNumber <= lastSequenceNumber {
			log.Warn("IngressWorker: Received stale sequence number", "last", lastSequenceNumber, "now", sequenceNumber)
			continue
		}
		if sequenceNumber != lastSequenceNumber+1 {
			log.Warn("IngressWorker: Unexpected sequence number", "last", lastSequenceNumber, "now", sequenceNumber)
			// Lost a frame somewhere, discard contents of partially built packet
			log.Warn("IngressWorker: Unable to reassemble IP packet, discarding previously received bytes",
				"bytesDiscarded", packetStart)
			discardContinuation = true
		}

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
				log.Error("IngressWorker: Unable to fit oversize IP packet", "bufferLen", cap(packet),
					"packetSize", packetStart+len(payload))
				packetStart = 0
				continue
			}
			copy(packet[packetStart:], payload)
			packetStart += len(payload)

			// Does the packet end here?
			if packetStart == reassembledLength {
				err = send(global, packet[:packetStart])
				if err != nil {
					log.Error("IngressWorker: Unable to send reassembled packet", "err", err)
					packetStart = 0
				}
				continue
			}

			// Packet continues in the next frame, nothing left to do here
			continue
		}

		// Reindex in C style, starting from 0
		index -= 1
		lastSequenceNumber = sequenceNumber

		// We only copy beginning of frame data if we haven't lost the previous one
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
			err := send(global, packet[:packetStart])
			if err != nil {
				log.Error("IngressWorker: Unable to send reassembled IP packet", "err", err)
			}
		}

		// Process remaining packets, reslice to beginning of first packet
		payload = payload[index:]
		packetStart = 0
		debuggerCounter := 0
		for {
			log.Debug("Loop iteration", "counter", debuggerCounter)
			debuggerCounter += 1

			// The start of this frame is part of a packet that's missing pieces,
			// start processing from the first valid packet
			version := uint8(payload[0]) >> 4
			if version != 4 {
				log.Warn("Unsupported IP version", "version", version)
				// Rest of packet cannot be reliably parsed, jump to next one
				continue ReceiveLoop
			}

			// Version is correct, grab total length
			length := int(common.Order.Uint16(payload[2:4]))
			log.Debug("Found IP packet", "length", length)

			if length > 1500 {
				log.Warn("Found large IP packet", "length", length)
			}

			if length > len(payload) {
				log.Debug("length > len(payload)", "length", length, "len(payload)", len(payload))
				// Need to reconstruct the full IP packet across frames
				log.Debug("IP packet extends past this frame", "totalLength", length,
					"in this frame", len(payload))
				copy(packet[packetStart:], payload)
				packetStart += len(payload)
				continue ReceiveLoop
			}

			if length == len(payload) {
				log.Debug("length = len(payload)", "length", length, "len(payload)", len(payload))
				// The end of the IP packet is the end of the frame
				err := send(global, payload)
				if err != nil {
					log.Error("Unable to send IP packet", "packet", payload)
					continue ReceiveLoop
				}
				continue ReceiveLoop
			}

			log.Debug("length < len(payload)", "length", length, "len(payload)", len(payload))
			// This frame contains data after this packet, try to parse another one
			payload = payload[length:]
		}
	}
}
