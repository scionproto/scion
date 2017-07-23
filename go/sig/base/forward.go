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
//   to determine where the first packet in the frame starts.
//
//      0B       1        2        3        4        5        6        7
//  +--------+--------+--------+--------+--------+--------+--------+--------+
//  |         Sequence number           |     Index       |      Epoch      |
//  +--------+--------+--------+--------+--------+--------+--------+--------+
//
const (
	SIGHdrSize          = 8
	PktLenSize          = 4
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

func sendFrame(conn net.Conn, frame []byte, seqNumber *uint32, index int, epoch uint16) error {
	log.Debug("sendFrame", "len", len(frame), "seq", *seqNumber, "index", index, "epoch", epoch)
	// Encapsulate and flush
	common.Order.PutUint32(frame[:4], *seqNumber)
	common.Order.PutUint16(frame[4:6], uint16(index))
	common.Order.PutUint16(frame[6:8], uint16(epoch))
	*seqNumber++
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

func EgressWorker(info *asInfo) {
	var seqNumber uint32

	// Continuously read from tunnel interface, putting data into pc
	bp := NewBufferPool()
	buffers := make(chan []byte, 128)
	go tunnelReader(info.Device, bp, buffers)

	frame := make([]byte, 1<<16)
	var pkt []byte
	var pktOff int
	var index int
	var flow net.Conn
	var err error
	var epoch uint16
	frameOff := SIGHdrSize
TopLoop:
	for {
		if seqNumber == 0 {
			epoch = uint16(time.Now().Unix() & 0xFFFF)
		}
		// FIXME(kormat): there's no reason we need to run this for _every_ packet.
		// also, this should be dropping old packets to keep the buffer queue clear.
		flow, err = info.getConn()
		if err != nil {
			log.Error("Unable to get flow", "err", err)
			// No connection is available, back off for 500ms and try again
			<-time.After(500 * time.Millisecond)
			continue
		}
		// FIXME(kormat): calculate the max payload size based on path's MTU
		frame = frame[:1280]
		log.Debug("Top of loop", "frameOff", frameOff, "seqNumber", seqNumber, "index", index)
		if frameOff == SIGHdrSize {
			// Don't have a partial frame, so block indefiniely for the next packet.
			pkt = <-buffers
			log.Debug("No partial frame, got new packet")
		} else {
			// Have partial frame
			select {
			case pkt = <-buffers:
				// Another packet was available, process it
				log.Debug("Have partial frame, got new packet")
			default:
				log.Debug("Have partial frame, no new packet, send partial frame",
					"frameOff", frameOff, "seqNumber", seqNumber, "index", index)
				// No packets available, send existing frame.
				err := sendFrame(flow, frame[:frameOff], &seqNumber, index, epoch)
				frameOff = SIGHdrSize
				index = 0
				if err != nil {
					log.Error("Error sending frame", "err", err)
				}
				bp.Put(pkt)
				continue TopLoop
			}
		}
		if index == 0 {
			// This is the first start of a packet in this frame, so set the index
			index = frameOff / 8
		}
		// Write packet length to frame
		common.Order.PutUint16(frame[frameOff:], uint16(len(pkt)))
		frameOff += 2
		pktOff = 0
		log.Debug("Starting to copy packet")
		// Write chunks of the packet to frames, sending off frames as they fill up.
		for {
			log.Debug("Copy packet top", "frameOff", frameOff, "pktOff", pktOff)
			copied := copy(frame[frameOff:], pkt[pktOff:])
			pktOff += copied
			frameOff += copied
			log.Debug("Copy packet middle", "frameOff", frameOff, "pktOff", pktOff, "copied", copied)
			if len(frame)-frameOff < PktLenSize*2 {
				// There's no point in trying to fit another packet into this frame.
				err := sendFrame(flow, frame[:frameOff], &seqNumber, index, epoch)
				frameOff = SIGHdrSize
				index = 0
				if err != nil {
					log.Error("Error sending frame", "err", err)
				}
			}
			if pktOff == len(pkt) {
				// This packet is now finished, time to get a new one.
				frameOff = pad(frameOff)
				bp.Put(pkt)
				continue TopLoop
			}
			// Otherwise continue copying packet into next frame.
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
