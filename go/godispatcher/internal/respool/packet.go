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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/spkt"
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
	Info          spkt.ScnPkt
	OverlayRemote *net.UDPAddr

	// buffer contains the raw slice that other fields reference
	buffer common.RawBytes

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

	pkt.OverlayRemote = readExtra.(*net.UDPAddr)
	if err = hpkt.ParseScnPkt(&pkt.Info, pkt.buffer); err != nil {
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
		return common.NewBasicError("missing next-hop", nil)
	}
	pkt.OverlayRemote = readExtra.(*overlay.OverlayAddr).ToUDPAddr()

	// XXX(scrye): We ignore the return value of packet parsing on egress
	// because some tests (e.g., the Python SCMP error test) rely on being able
	// to dump bad SCION packets on the network. If the error here is taken
	// into account, the dispatcher drops the packet and the SCMP error reply
	// never comes back from the BR.
	_ = hpkt.ParseScnPkt(&pkt.Info, pkt.buffer)
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
}
