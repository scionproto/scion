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
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet/internal/metrics"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
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
type Bytes common.RawBytes

// Prepare readies a layer's storage for use.
//
// If the layer is not allocated, a backing buffer of maximum packet size is
// allocated.
//
// If the layer is already allocated, its length is reset to its capacity.
func (b *Bytes) Prepare() {
	if *b == nil {
		*b = make(Bytes, common.MaxMTU)
	}
	*b = (*b)[:cap(*b)]
}

type Packet struct {
	Bytes
	PacketInfo
}

// PacketInfo contains the data needed to construct a SCION packet.
//
// This is a high-level structure, and can only be used to create valid
// packets. The documentation for each field specifies cases where
// serialization might fail due to some violation of SCION protocol rules.
type PacketInfo struct {
	// Destination contains the destination address.
	Destination SCIONAddress
	// Source contains the source address. If it is an SVC address, packet
	// serialization will return an error.
	Source SCIONAddress
	// Path contains a SCION forwarding path. The field must be nil or an empty
	// path if the source and destination are inside the same AS.
	//
	// If the source and destination are in different ASes but the path is
	// nil or empty, an error is returned during serialization.
	Path *spath.Path
	// Extensions contains SCION HBH and E2E extensions. When received from a
	// RawSCIONConn, extensions are present in the order they were found in the packet.
	//
	// When writing to a RawSCIONConn, the serializer will attempt
	// to reorder the extensions, depending on their type, in the correct
	// order. If the number of extensions is over the limit allowed by SCION,
	// serialization will fail. Whenever multiple orders are valid, the stable
	// sorting is preferred. The extensions are sorted in place, so callers
	// should expect the order to change after a write.
	//
	// The SCMP HBH extension needs to be manually included by calling code,
	// even when the L4Header and Payload demand one (as is the case, for
	// example, for a SCMP::General::RecordPathRequest packet).
	Extensions []common.Extension
	// L4Header contains L4 header information.
	L4Header l4.L4Header
	Payload  common.Payload
}

// SCIONAddress is the fully-specified address of a host.
type SCIONAddress struct {
	IA   addr.IA
	Host addr.HostAddr
}

// SCIONPacketConn gives applications full control over the content of valid SCION
// packets.
type SCIONPacketConn struct {
	// conn is the connection to send/receive serialized packets on.
	conn net.PacketConn
	// scmpHandler is invoked for packets that contain an SCMP L4. If the
	// handler is nil, errors are returned back to applications every time an
	// SCMP message is received.
	scmpHandler SCMPHandler
}

// NewSCIONPacketConn creates a new conn with packet serialization/decoding
// support that transfers data over conn.
func NewSCIONPacketConn(conn net.PacketConn, scmpHandler SCMPHandler) *SCIONPacketConn {
	return &SCIONPacketConn{
		conn:        conn,
		scmpHandler: scmpHandler,
	}
}

func (c *SCIONPacketConn) SetDeadline(d time.Time) error {
	return c.conn.SetDeadline(d)
}

func (c *SCIONPacketConn) Close() error {
	metrics.M.Closes().Inc()
	return c.conn.Close()
}

func (c *SCIONPacketConn) WriteTo(pkt *Packet, ov *net.UDPAddr) error {
	StableSortExtensions(pkt.Extensions)
	hbh, e2e, err := hpkt.ValidateExtensions(pkt.Extensions)
	if err != nil {
		return common.NewBasicError("Bad extension list", err)
	}
	// TODO(scrye): scnPkt is a temporary solution. Its functionality will be
	// absorbed by the easier to use Packet structure in this package.
	scnPkt := &spkt.ScnPkt{
		DstIA:   pkt.Destination.IA,
		SrcIA:   pkt.Source.IA,
		DstHost: pkt.Destination.Host,
		SrcHost: pkt.Source.Host,
		E2EExt:  e2e,
		HBHExt:  hbh,
		Path:    pkt.Path,
		L4:      pkt.L4Header,
		Pld:     pkt.Payload,
	}
	pkt.Prepare()
	n, err := hpkt.WriteScnPkt(scnPkt, common.RawBytes(pkt.Bytes))
	if err != nil {
		return common.NewBasicError("Unable to serialize SCION packet", err)
	}
	pkt.Bytes = pkt.Bytes[:n]
	// Send message
	n, err = c.conn.WriteTo(pkt.Bytes, ov)
	if err != nil {
		return common.NewBasicError("Reliable socket write error", err)
	}
	metrics.M.WriteBytes().Add(float64(n))
	metrics.M.WritePackets().Inc()
	return nil
}

func (c *SCIONPacketConn) SetWriteDeadline(d time.Time) error {
	return c.conn.SetWriteDeadline(d)
}

func (c *SCIONPacketConn) ReadFrom(pkt *Packet, ov *net.UDPAddr) error {
	for {
		// Read until we get an error or a data packet
		if err := c.readFrom(pkt, ov); err != nil {
			return err
		}
		if scmpHdr, ok := pkt.L4Header.(*scmp.Hdr); ok {
			if c.scmpHandler == nil {
				metrics.M.SCMPErrors().Inc()
				return common.NewBasicError("scmp packet received, but no handler found", nil,
					"scmp.Hdr", scmpHdr, "src", pkt.Source)
			}
			if err := c.scmpHandler.Handle(pkt); err != nil {
				// Return error intact s.t. applications can handle custom
				// error types returned by SCMP handlers.
				return err
			}
		} else {
			// non-SCMP L4s are assumed to be data and get passed back to the
			// app.
			return nil
		}
	}
}

func (c *SCIONPacketConn) readFrom(pkt *Packet, ov *net.UDPAddr) error {
	pkt.Prepare()
	n, lastHopNetAddr, err := c.conn.ReadFrom(pkt.Bytes)
	if err != nil {
		metrics.M.DispatcherErrors().Inc()
		return common.NewBasicError("Reliable socket read error", err)
	}
	metrics.M.ReadBytes().Add(float64(n))
	metrics.M.ReadPackets().Inc()

	pkt.Bytes = pkt.Bytes[:n]
	var lastHop *net.UDPAddr

	var ok bool
	lastHop, ok = lastHopNetAddr.(*net.UDPAddr)
	if !ok {
		return common.NewBasicError("Invalid lastHop address Type", nil,
			"Actual", lastHopNetAddr)
	}

	// TODO(scrye): scnPkt is a temporary solution. Its functionality will be
	// absorbed by the easier to use Packet structure in this package.
	scnPkt := &spkt.ScnPkt{
		DstIA: addr.IA{},
		SrcIA: addr.IA{},
	}
	err = hpkt.ParseScnPkt(scnPkt, common.RawBytes(pkt.Bytes))
	if err != nil {
		metrics.M.ParseErrors().Inc()
		return common.NewBasicError("SCION packet parse error", err)
	}

	pkt.Destination = SCIONAddress{IA: scnPkt.DstIA, Host: scnPkt.DstHost}
	pkt.Source = SCIONAddress{IA: scnPkt.SrcIA, Host: scnPkt.SrcHost}
	pkt.Path = scnPkt.Path
	pkt.Extensions = append(pkt.Extensions, scnPkt.HBHExt...)
	pkt.Extensions = append(pkt.Extensions, scnPkt.E2EExt...)
	pkt.L4Header = scnPkt.L4
	pkt.Payload = scnPkt.Pld
	if ov != nil {
		*ov = *lastHop
	}
	return nil
}

func (c *SCIONPacketConn) SetReadDeadline(d time.Time) error {
	return c.conn.SetReadDeadline(d)
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

// StableSortExtensions sorts the extensions in data in place. The sort is stable.
//
// SCMP extensions are moved to the start of the slice, followed by HBH
// extensions and finally E2E extensions.
//
// StableSortExtensions performs no validations on the number and/or types of
// extensions.
//
// The function panics if data is nil.
func StableSortExtensions(data []common.Extension) {
	sort.SliceStable(data, func(i, j int) bool {
		return compareExtensions(data[i], data[j])
	})
}

func compareExtensions(x, y common.Extension) bool {
	return getPriority(x) < getPriority(y)
}

func getPriority(x common.Extension) int {
	switch x.Class() {
	case common.HopByHopClass:
		if x.Type() == common.ExtnSCMPType {
			return 10
		}
		return 20
	case common.End2EndClass:
		return 30
	default:
		return 100
	}
}
