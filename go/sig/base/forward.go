package base

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/pring"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
	"github.com/netsec-ethz/scion/go/sig/metrics"
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

type EgressWorker struct {
	info  *asInfo
	src   io.ReadWriteCloser
	c     chan common.RawBytes
	pRing *pring.PRing

	epoch    uint16
	seq      uint32
	index    uint16
	frameOff int
}

const EgressChanSize = 128

func NewEgressWorker(info *asInfo) *EgressWorker {
	return &EgressWorker{
		info:  info,
		src:   info.Device,
		pRing: pring.New(1 << 24),
	}
}

func (e *EgressWorker) Run() error {
	// Start reader goroutine
	go e.Read()

	frame := make(common.RawBytes, 1<<16)
	var conn net.Conn
	e.frameOff = SIGHdrSize
	readBuffer := make(common.RawBytes, 1<<24)

	for {
		readBytes, err := e.pRing.Read(readBuffer)
		if err != nil {
			log.Error("Error while reading from PacketRing", "err", err)
			continue
		}
		pr := NewPacketReader(readBuffer[:readBytes])

		// FIXME(kormat): there's no reason we need to run this for _every_ packet.
		// also, this should be dropping old packets to keep the buffer queue clear.
		conn, err = e.info.getConn()
		if err != nil {
			log.Error("Unable to get conn", "err", err)
			// No connection is available, back off for 500ms and try again
			<-time.After(500 * time.Millisecond)
			continue
		}
		// FIXME(kormat): calculate the max payload size based on path's MTU
		frame = frame[:1280]

		for {
			pkt, err := pr.nextPacket()
			if err != nil {
				log.Error("Error retrieving next packet", "err", err)
				break
			}
			if pkt == nil {
				break
			}
			if err := e.CopyPkt(conn, frame, pkt); err != nil {
				log.Error("Error sending frame", "err", err)
			}
		}
		// If bytes remaining, flush them
		if e.frameOff != SIGHdrSize {
			err := e.Write(conn, frame[:e.frameOff])
			if err != nil {
				log.Error("Error sending frame", "err", err)
			}
		}
	}
}

func (e *EgressWorker) CopyPkt(conn net.Conn, frame, pkt common.RawBytes) error {
	// New packets always starts at a 8 byte boundary.
	e.frameOff = pad(e.frameOff)
	if e.index == 0 {
		// This is the first start of a packet in this frame, so set the index
		e.index = uint16(e.frameOff / 8)
	}
	// Write packet length to frame
	common.Order.PutUint16(frame[e.frameOff:], uint16(len(pkt)))
	e.frameOff += PktLenSize
	pktOff := 0
	// Write chunks of the packet to frames, sending off frames as they fill up.
	for {
		copied := copy(frame[e.frameOff:], pkt[pktOff:])
		pktOff += copied
		e.frameOff += copied
		if len(frame)-e.frameOff < MinSpace {
			// There's no point in trying to fit another packet into this frame.
			if err := e.Write(conn, frame[:e.frameOff]); err != nil {
				// Skip the rest of this packet.
				return err
			}
		}
		if pktOff == len(pkt) {
			// This packet is now finished, time to get a new one.
			return nil
		}
		// Otherwise continue copying packet into next frame.
	}
}

func (e *EgressWorker) Read() {
	pktBuffer := make([]byte, 1<<16)
	for {
		// Leave 2 bytes for length
		bytesRead, err := e.src.Read(pktBuffer[2:])
		if err != nil {
			log.Error("Egress read error", "err", err)
			return
		}
		if bytesRead > common.MaxMTU {
			log.Error("Read oversized packet from tun", "length", bytesRead)
			continue
		}
		binary.BigEndian.PutUint16(pktBuffer[:2], uint16(bytesRead))
		_, err = e.pRing.Write(pktBuffer[:bytesRead+2])
		if err != nil {
			log.Error("PacketRing write error", "err", err)
			return
		}

		metrics.PktsRecv.WithLabelValues(e.info.DeviceName).Inc()
		metrics.PktBytesRecv.WithLabelValues(e.info.DeviceName).Add(float64(bytesRead))
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
	bytesWritten, err := conn.Write(frame)
	if err != nil {
		return common.NewError("Egress write error", "err", err)
	}
	metrics.FramesSent.WithLabelValues(e.info.Name).Inc()
	metrics.FrameBytesSent.WithLabelValues(e.info.Name).Add(float64(bytesWritten))
	return nil
}

type PacketReader struct {
	buffer []byte
	index  int
}

func NewPacketReader(buffer []byte) *PacketReader {
	pr := &PacketReader{}
	pr.buffer = buffer
	return pr
}

func (pr *PacketReader) nextPacket() ([]byte, error) {
	if pr.index >= len(pr.buffer) {
		return nil, nil
	}
	length := int(binary.BigEndian.Uint16(pr.buffer[pr.index : pr.index+2]))
	pr.index += 2
	packet := pr.buffer[pr.index : pr.index+length]
	pr.index += length
	return packet, nil
}
