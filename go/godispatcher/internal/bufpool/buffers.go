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

// Package buffers contains the Dispatcher's pool of free buffers.
//
// FIXME(scrye): Currently the pool is elastic, but this is not ideal for
// traffic bursts. It should probably be replaced with a fixed-sized list.
package bufpool

import (
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/spkt"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make(common.RawBytes, common.MaxMTU)
	},
}

func GetBuffer() common.RawBytes {
	b := bufferPool.Get().(common.RawBytes)
	return b[:cap(b)]
}

func PutBuffer(b common.RawBytes) {
	if cap(b) == common.MaxMTU {
		bufferPool.Put(b)
	}
}

var packetPool = sync.Pool{
	New: func() interface{} {
		return newPacket()
	},
}

func GetPacket() *Packet {
	return packetPool.Get().(*Packet)
}

func PutPacket(pkt *Packet) {
	pkt.reset()
	packetPool.Put(pkt)
}

// Packet describes a SCION packet. Fields might reference each other
// (including hidden fields), so callers should only write to freshly created
// packets, and readers should take care never to mutate data.
type Packet struct {
	Info          spkt.ScnPkt
	OverlayRemote *net.UDPAddr

	// buffer contains the raw slice that other fields reference
	buffer common.RawBytes
	data   common.RawBytes

	mtx      sync.Mutex
	refCount *int
}

func newPacket() *Packet {
	refCount := 1
	return &Packet{
		buffer:   GetBuffer(),
		refCount: &refCount,
	}
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

// Free releases a reference to the packet. Free is safe to use from concurrent
// goroutines.
func (pkt *Packet) Free() {
	pkt.mtx.Lock()
	if *pkt.refCount <= 0 {
		panic("reference count underflow")
	}
	*pkt.refCount--
	if *pkt.refCount == 0 {
		PutBuffer(pkt.buffer)
		// Prevent use after free bugs
		pkt.OverlayRemote = nil
		pkt.buffer = nil
		pkt.Info = spkt.ScnPkt{}
	}
	pkt.mtx.Unlock()
}

func (pkt *Packet) DecodeFromConn(conn net.PacketConn) error {
	n, readExtra, err := conn.ReadFrom(pkt.buffer)
	if err != nil {
		return common.NewBasicError("read error", err)
	}
	pkt.buffer = pkt.buffer[:n]

	if readExtra == nil {
		return common.NewBasicError("missing next-hop", nil)
	}
	switch address := readExtra.(type) {
	case *net.UDPAddr:
		pkt.OverlayRemote = address
	case *overlay.OverlayAddr:
		pkt.OverlayRemote = address.ToUDPAddr()
	default:
		return common.NewBasicError("unsupported next-hop type", nil, "address", address)
	}

	if err := hpkt.ParseScnPkt(&pkt.Info, pkt.buffer); err != nil {
		return common.NewBasicError("parse error", err)
	}
	return nil
}

func (pkt *Packet) SendOnConn(conn net.PacketConn, address net.Addr) error {
	_, err := conn.WriteTo(pkt.buffer, address)
	return err
}

func (pkt *Packet) reset() {
	pkt.buffer = pkt.buffer[:cap(pkt.buffer)]
	pkt.Info = spkt.ScnPkt{}
	pkt.OverlayRemote = nil
	*pkt.refCount = 0
}
