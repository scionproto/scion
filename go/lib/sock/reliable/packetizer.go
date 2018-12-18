// Copyright 2018 ETH Zurich
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

package reliable

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// ReadPacketizer splits a stream of reliable socket frames into packets.
//
// FIXME(scrye): This will be deleted when we move to SEQPACKET.
type ReadPacketizer struct {
	buffer    [1 << 16]byte
	data      []byte
	freeSpace []byte
	conn      net.Conn
}

func NewReadPacketizer(conn net.Conn) *ReadPacketizer {
	packetizer := &ReadPacketizer{conn: conn}
	packetizer.freeSpace = packetizer.buffer[:]
	packetizer.data = packetizer.buffer[0:0]
	return packetizer
}

func (r *ReadPacketizer) Read(b []byte) (int, error) {
	for {
		if packet := r.haveNextPacket(r.data); packet != nil {
			if len(packet) > len(b) {
				return 0, common.NewBasicError(ErrBufferTooSmall, nil,
					"have", len(b), "want", len(packet))
			}
			copy(b, packet)
			r.deleteData(len(packet))
			return len(packet), nil
		}
		n, err := r.conn.Read(r.freeSpace)
		if err != nil {
			return 0, err
		}
		r.addData(n)
	}
}

func (r *ReadPacketizer) deleteData(count int) {
	copy(r.buffer[:], r.buffer[count:r.availableData()])
	r.updateSlices(r.availableData() - count)
}

func (r *ReadPacketizer) addData(count int) {
	r.updateSlices(r.availableData() + count)
}

func (r *ReadPacketizer) availableData() int {
	return len(r.data)
}

func (r *ReadPacketizer) updateSlices(availableData int) {
	r.data = r.buffer[:availableData]
	r.freeSpace = r.buffer[availableData:]
}

// haveNextPacket returns a slice with the next packet in b, or nil, if a full
// packet is not available.
func (reader *ReadPacketizer) haveNextPacket(b []byte) []byte {
	if len(b) < 13 {
		return nil
	}
	rcvdAddrType := b[8]
	payloadLength := common.Order.Uint32(b[9:13])
	addressLength := getAddressLength(addr.HostAddrType(rcvdAddrType))
	portLength := getPortLength(addr.HostAddrType(rcvdAddrType))
	totalLength := 13 + addressLength + portLength + int(payloadLength)
	if len(b) < totalLength {
		return nil
	}
	return b[:totalLength]
}

// WriteStreamer sends a packet via a stream. It is guaranteed to block until
// the whole packet has been sent (or an error occurred).
//
// FIXME(scrye): This will be delete when we move to SEQPACKET.
type WriteStreamer struct {
	conn net.Conn
}

func NewWriteStreamer(conn net.Conn) *WriteStreamer {
	return &WriteStreamer{conn: conn}
}

func (writer *WriteStreamer) Write(b []byte) error {
	var err error
	for bytesWritten, n := 0, 0; bytesWritten != len(b); bytesWritten += n {
		n, err = writer.conn.Write(b[bytesWritten:])
		if err != nil {
			return err
		}
	}
	return nil
}
