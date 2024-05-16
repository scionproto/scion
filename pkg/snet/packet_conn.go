// Copyright 2019 ETH Zurich, Anapaya Systems
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

package snet

import (
	"net"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

// PacketConn gives applications easy access to writing and reading custom
// SCION packets.
type PacketConn interface {
	ReadFrom(pkt *Packet, ov *net.UDPAddr) error
	WriteTo(pkt *Packet, ov *net.UDPAddr) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SetDeadline(t time.Time) error
	Close() error
}

// Bytes contains the raw slices of data related to a packet. Most callers
// can safely ignore it. For performance-critical applications, callers should
// manually allocate/recycle the Bytes.
//
// Prior to serialization/decoding, the internal slice is reset to its full
// capacity, so be careful about passing in slices that have runoff data after
// their length.
//
// After a packet has been serialized/decoded, the length of Contents will be
// equal to the size of the entire packet data. The capacity remains unchanged.
//
// If Bytes is not initialized, space will be allocated during
// serialization/decoding.
type Bytes []byte

// Prepare readies a layer's storage for use.
//
// If the layer is not allocated, a backing buffer of maximum packet size is
// allocated.
//
// If the layer is already allocated, its length is reset to its capacity.
func (b *Bytes) Prepare() {
	if *b == nil {
		*b = make(Bytes, common.SupportedMTU)
	}
	*b = (*b)[:cap(*b)]
}

type L4Header interface {
	closed()
}

type UDPL4 struct {
	slayers.UDP
}

func (UDPL4) closed() {}

type SCMPExternalInterfaceDownL4 struct {
	slayers.SCMPExternalInterfaceDown
}

func (SCMPExternalInterfaceDownL4) closed() {}

// SCIONAddress is the fully-specified address of a host.
type SCIONAddress = addr.Addr

type SCIONPacketConnMetrics struct {
	// Closes records the total number of Close calls on the connection.
	Closes metrics.SimpleCounter
	// ReadBytes records the total number of bytes read on the connection.
	ReadBytes metrics.SimpleCounter
	// WriteBytes records the total number of bytes written on the connection.
	WriteBytes metrics.SimpleCounter
	// ReadPackets records the total number of packets read on the connection.
	ReadPackets metrics.SimpleCounter
	// WritePackets records the total number of packets written on the connection.
	WritePackets metrics.SimpleCounter
	// ParseErrors records the total number of parse errors encountered.
	ParseErrors metrics.SimpleCounter
	// SCMPErrors records the total number of SCMP Errors encountered.
	SCMPErrors metrics.SimpleCounter
	// DispatcherErrors records the number of dispatcher errors encountered.
	DispatcherErrors metrics.SimpleCounter
}

// SCIONPacketConn gives applications full control over the content of valid SCION
// packets.
type SCIONPacketConn struct {
	// Conn is the connection to send/receive serialized packets on.
	Conn net.PacketConn
	// SCMPHandler is invoked for packets that contain an SCMP L4. If the
	// handler is nil, errors are returned back to applications every time an
	// SCMP message is received.
	SCMPHandler SCMPHandler
	// Metrics are the metrics exported by the conn.
	Metrics SCIONPacketConnMetrics
}

func (c *SCIONPacketConn) SetDeadline(d time.Time) error {
	return c.Conn.SetDeadline(d)
}

func (c *SCIONPacketConn) Close() error {
	metrics.CounterInc(c.Metrics.Closes)
	return c.Conn.Close()
}

func (c *SCIONPacketConn) WriteTo(pkt *Packet, ov *net.UDPAddr) error {
	if err := pkt.Serialize(); err != nil {
		return serrors.WrapStr("serialize SCION packet", err)
	}

	// Send message
	n, err := c.Conn.WriteTo(pkt.Bytes, ov)
	if err != nil {
		return serrors.WrapStr("Reliable socket write error", err)
	}
	metrics.CounterAdd(c.Metrics.WriteBytes, float64(n))
	metrics.CounterInc(c.Metrics.WritePackets)
	return nil
}

func (c *SCIONPacketConn) SetWriteDeadline(d time.Time) error {
	return c.Conn.SetWriteDeadline(d)
}

func (c *SCIONPacketConn) ReadFrom(pkt *Packet, ov *net.UDPAddr) error {
	for {
		// Read until we get an error or a data packet
		if err := c.readFrom(pkt, ov); err != nil {
			return err
		}
		if scmp, ok := pkt.Payload.(SCMPPayload); ok {
			if c.SCMPHandler == nil {
				metrics.CounterInc(c.Metrics.SCMPErrors)
				return serrors.New("scmp packet received, but no handler found",
					"type_code", slayers.CreateSCMPTypeCode(scmp.Type(), scmp.Code()),
					"src", pkt.Source)
			}
			if err := c.SCMPHandler.Handle(pkt); err != nil {
				// Return error intact s.t. applications can handle custom
				// error types returned by SCMP handlers.
				return err
			}
			continue
		}
		// non-SCMP L4s are assumed to be data and get passed back to the
		// app.
		return nil
	}
}

func (c *SCIONPacketConn) readFrom(pkt *Packet, ov *net.UDPAddr) error {
	pkt.Prepare()
	n, lastHopNetAddr, err := c.Conn.ReadFrom(pkt.Bytes)
	if err != nil {
		metrics.CounterInc(c.Metrics.DispatcherErrors)
		return serrors.WrapStr("Reliable socket read error", err)
	}
	metrics.CounterAdd(c.Metrics.ReadBytes, float64(n))
	metrics.CounterInc(c.Metrics.ReadPackets)

	pkt.Bytes = pkt.Bytes[:n]
	var lastHop *net.UDPAddr

	var ok bool
	lastHop, ok = lastHopNetAddr.(*net.UDPAddr)
	if !ok {
		return serrors.New("Invalid lastHop address Type",
			"Actual", lastHopNetAddr)
	}

	if err := pkt.Decode(); err != nil {
		metrics.CounterInc(c.Metrics.ParseErrors)
		return serrors.WrapStr("decoding packet", err)
	}

	if ov != nil {
		*ov = *lastHop
	}
	return nil
}

func (c *SCIONPacketConn) SetReadDeadline(d time.Time) error {
	return c.Conn.SetReadDeadline(d)
}

type SerializationOptions struct {
	// If ComputeChecksums is true, the checksums in sent Packets are
	// recomputed. Otherwise, the checksum value is left intact.
	ComputeChecksums bool
	// If FixLengths is true, any lengths in sent Packets are recomputed
	// to match the data contained in payloads/inner layers. This currently
	// concerns extension headers and the L4 header.
	FixLengths bool
	// If InitializePaths is set to true, then forwarding paths are reset to
	// their starting InfoField/HopField during serialization, irrespective of
	// previous offsets. If it is set to false, then the fields are left
	// unchanged.
	InitializePaths bool
}
