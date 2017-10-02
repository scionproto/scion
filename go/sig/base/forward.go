// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package base

import (
	"io"
	"net"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
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
	SIGHdrSize = 8
	PktLenSize = 2
	MinSpace   = 16
)

type BufferPool struct {
	pool *sync.Pool
}

func NewBufferPool() *BufferPool {
	new := func() interface{} {
		return make(common.RawBytes, 64*1024)
	}
	bp := &BufferPool{
		pool: &sync.Pool{New: new},
	}
	for i := 0; i < 32; i++ {
		bp.Put(make(common.RawBytes, 64*1024))
	}
	return bp
}

func (bp *BufferPool) Get() common.RawBytes {
	// Reset slice to entire buffer
	b := bp.pool.Get().(common.RawBytes)
	return b[:cap(b)]
}

func (bp *BufferPool) Put(b common.RawBytes) {
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

		if e.frameOff == SIGHdrSize {
			// Don't have a partial frame, so block indefiniely for the next packet.
			pkt = <-e.c
		} else {
			// Have partial frame
			select {
			case pkt = <-e.c:
				// Another packet was available, process it
			default:
				// No packets available, send existing frame.
				err := e.Write(conn, frame[:e.frameOff])
				if err != nil {
					log.Error("Error sending frame", "err", err)
				}
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
	// New packets always starts at a 8 byte boundary.
	e.frameOff += util.CalcPadding(e.frameOff, 8)
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
	for {
		pktBuffer := e.bp.Get()
		bytesRead, err := e.src.Read(pktBuffer)
		if err != nil {
			log.Error("Egress read error", "err", err)
			return
		}
		e.c <- pktBuffer[:bytesRead]
		metrics.PktsRecv.WithLabelValues(e.info.DeviceName).Inc()
		metrics.PktBytesRecv.WithLabelValues(e.info.DeviceName).Add(float64(bytesRead))
	}
}

func (e *EgressWorker) Write(conn net.Conn, frame common.RawBytes) error {
	if e.seq == 0 {
		e.epoch = uint16(time.Now().Unix() & 0xFFFF)
	}
	//log.Debug("EgressWorker.Write", "len", len(frame), "epoch", e.epoch,
	//	"seq", e.seq, "index", e.index)

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
		return common.NewCError("Egress write error", "err", err)
	}
	metrics.FramesSent.WithLabelValues(e.info.Name).Inc()
	metrics.FrameBytesSent.WithLabelValues(e.info.Name).Add(float64(bytesWritten))
	return nil
}
