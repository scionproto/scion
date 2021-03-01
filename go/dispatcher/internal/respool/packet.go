// Copyright 2019 ETH Zurich
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

package respool

import (
	"net"
	"sync"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/dispatcher/internal/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
)

var packetPool = sync.Pool{
	New: func() interface{} {
		return newPacket()
	},
}

func GetPacket() *Packet {
	pkt := packetPool.Get().(*Packet)
	*pkt.refCount = 1
	return pkt
}

// Packet describes a SCION packet. Fields might reference each other
// (including hidden fields), so callers should only write to freshly created
// packets, and readers should take care never to mutate data.
type Packet struct {
	UnderlayRemote *net.UDPAddr

	SCION slayers.SCION
	// FIXME(roosd): currently no support for extensions.
	UDP  slayers.UDP
	SCMP slayers.SCMP

	// L4 indicates what type is at layer 4.
	L4 gopacket.LayerType

	// parser is tied to the layers in this packet.
	// IngoreUnsupported is set to true.
	parser *gopacket.DecodingLayerParser
	// buffer contains the raw slice that other fields reference
	buffer []byte

	mtx      sync.Mutex
	refCount *int
}

// Len returns the length of the packet.
func (p *Packet) Len() int {
	return len(p.buffer)
}

func newPacket() *Packet {
	refCount := 1
	pkt := &Packet{
		buffer:   GetBuffer(),
		refCount: &refCount,
	}
	pkt.parser = gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION,
		&pkt.SCION, &pkt.UDP, &pkt.SCMP,
	)
	pkt.parser.IgnoreUnsupported = true
	return pkt
}

// Dup increases pkt's reference count.
//
// Dup panics if it is called after the packet has been freed (i.e., it's
// reference count reached 0).
//
// Modifying a packet after the first call to Dup is racy, and callers should
// use external locking for it.
func (pkt *Packet) Dup() {
	pkt.mtx.Lock()
	if *pkt.refCount <= 0 {
		panic("cannot reference freed packet")
	}
	*pkt.refCount++
	pkt.mtx.Unlock()
}

// CopyTo copies the buffer into the provided bytearray. Returns number of bytes copied.
func (pkt *Packet) CopyTo(p []byte) int {
	n := len(pkt.buffer)
	p = p[:n]
	copy(p, pkt.buffer)
	return n
}

// Free releases a reference to the packet. Free is safe to use from concurrent
// goroutines.
func (pkt *Packet) Free() {
	pkt.mtx.Lock()
	if *pkt.refCount <= 0 {
		panic("reference count underflow")
	}
	*pkt.refCount--
	if *pkt.refCount == 0 {
		pkt.reset()
		pkt.mtx.Unlock()
		packetPool.Put(pkt)
	} else {
		pkt.mtx.Unlock()
	}
}

func (pkt *Packet) DecodeFromConn(conn net.PacketConn) error {
	n, readExtra, err := conn.ReadFrom(pkt.buffer)
	if err != nil {
		return err
	}
	pkt.buffer = pkt.buffer[:n]
	metrics.M.NetReadBytes().Add(float64(n))

	pkt.UnderlayRemote = readExtra.(*net.UDPAddr)
	if err := pkt.decodeBuffer(); err != nil {
		metrics.M.NetReadPkts(
			metrics.IncomingPacket{
				Result: metrics.PacketResultParseError,
			},
		).Inc()
		return err
	}
	return nil
}

func (pkt *Packet) DecodeFromReliableConn(conn net.PacketConn) error {
	n, readExtra, err := conn.ReadFrom(pkt.buffer)
	if err != nil {
		return err
	}
	pkt.buffer = pkt.buffer[:n]

	if readExtra == nil {
		return serrors.New("missing next-hop")
	}
	pkt.UnderlayRemote = readExtra.(*net.UDPAddr)
	return pkt.decodeBuffer()
}

func (pkt *Packet) decodeBuffer() error {
	decoded := make([]gopacket.LayerType, 3)

	// Unsupported layers are ignored by the parser.
	if err := pkt.parser.DecodeLayers(pkt.buffer, &decoded); err != nil {
		return err
	}
	if len(decoded) < 2 {
		return serrors.New("L4 not decoded")
	}
	l4 := decoded[len(decoded)-1]
	if l4 != slayers.LayerTypeSCMP && l4 != slayers.LayerTypeSCIONUDP {
		return serrors.New("unknown L4 layer decoded", "type", l4)
	}
	pkt.L4 = l4
	return nil
}

func (pkt *Packet) SendOnConn(conn net.PacketConn, address net.Addr) (int, error) {
	return conn.WriteTo(pkt.buffer, address)
}

func (pkt *Packet) reset() {
	pkt.buffer = pkt.buffer[:cap(pkt.buffer)]
	pkt.UnderlayRemote = nil
	pkt.L4 = 0
}
