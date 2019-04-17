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

// Package svc implements support for SVC Resolution.
package svc

import (
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

const ErrHandler = "Unable to handle SVC request"

// NewResolverPacketDispatcher creates a dispatcher service that returns
// sockets with built-in SVC address resolution capabilities.
func NewResolverPacketDispatcher(d snet.PacketDispatcherService,
	h RequestHandler) *ResolverPacketDispatcher {

	return &ResolverPacketDispatcher{dispService: d, handler: h}
}

var _ snet.PacketDispatcherService = (*ResolverPacketDispatcher)(nil)

// ResolverPacketDispatcher is a dispatcher service that returns sockets with
// built-in SVC address resolution capabilities. Every packet received with a
// destination SVC address is intercepted inside the socket, and sent to an SVC
// resolution handler which responds back to the client.
//
// Redirected packets are not returned by the connection, so they cannot be
// seen via ReadFrom. After redirecting a packet, the connection attempts to
// read another packet before returning, until a non SVC packet is received or
// an error occurs.
type ResolverPacketDispatcher struct {
	dispService snet.PacketDispatcherService
	handler     RequestHandler
}

func (d *ResolverPacketDispatcher) RegisterTimeout(ia addr.IA, public *addr.AppAddr,
	bind *overlay.OverlayAddr, svc addr.HostSVC,
	timeout time.Duration) (snet.PacketConn, uint16, error) {

	c, port, err := d.dispService.RegisterTimeout(ia, public, bind, svc, timeout)
	if err != nil {
		return nil, 0, err
	}
	return &resolverPacketConn{PacketConn: c, handler: d.handler}, port, err
}

// resolverPacketConn redirects SVC destination packets to SVC resolution
// handler logic.
type resolverPacketConn struct {
	// PacketConn is the conn to receive and send packets.
	snet.PacketConn
	// handler handles packets for SVC destinations.
	handler RequestHandler
}

func (c *resolverPacketConn) ReadFrom(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
	for {
		if err := c.PacketConn.ReadFrom(pkt, ov); err != nil {
			return err
		}
		// XXX(scrye): destination address is guaranteed to not be nil
		if svc, ok := pkt.Destination.Host.(addr.HostSVC); ok {
			// Multicasts do not trigger SVC resolution logic
			if svc.IsMulticast() {
				return nil
			}
			// XXX(scrye): This might block, causing the read to wait for the
			// write to go through. The solution would be to run the logic in a
			// goroutine, but because UDP writes rarely block, the current
			// solution should be good enough for now.
			if err := c.handler.Handle(pkt, ov); err != nil {
				return common.NewBasicError(ErrHandler, err)
			}
			continue
		}
		// Normal packet, return to caller because data is already parsed and ready
		return nil
	}
}

// RequestHandler handles SCION packets with SVC destination addresses.
type RequestHandler interface {
	// Handle replies to SCION packets with SVC destinations coming from the
	// specified overlay address.
	//
	// Handle implementantions might panic if the destination is not an SVC
	// address, so callers should perform the check beforehand.
	Handle(*snet.SCIONPacket, *overlay.OverlayAddr) error
}

var _ RequestHandler = (*DefaultHandler)(nil)

// DefaultHandler reverses a SCION packet, replaces the source address with the
// one in the struct and then sends the message on the connection.
type DefaultHandler struct {
	// Source is the override value for the source address of the reply packet.
	Source snet.SCIONAddress
	// Conn is the connection to send the reply on. Conn must not be nil.
	Conn snet.PacketConn
	// Payload is the payload data to send in the reply. Nil and zero-length
	// payloads are supported.
	Payload []byte
	// Precheck runs on every packet passed into the reply sender. If the
	// precheck function returns an error, processing of the packet stops.
	// Precheck can be nil, in which case no checks are performed and every
	// packet is processed normally.
	Precheck Prechecker
}

func (h *DefaultHandler) Handle(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
	if h.Precheck != nil {
		if err := h.Precheck.Precheck(pkt); err != nil {
			return err
		}
	}
	path, err := h.reversePath(pkt.Path)
	if err != nil {
		return err
	}
	l4header := h.reverseL4Header(pkt.L4Header)
	replyPacket := &snet.SCIONPacket{
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Destination: pkt.Source,
			Source:      h.Source,
			Path:        path,
			L4Header:    l4header,
			Payload:     h.getPayload(),
		},
	}
	return h.Conn.WriteTo(replyPacket, ov)
}

func (h *DefaultHandler) reversePath(path *spath.Path) (*spath.Path, error) {
	if !path.IsEmpty() {
		// Reverse copy to not modify input packet
		path = path.Copy()
		if err := path.Reverse(); err != nil {
			return path, err
		}
	}
	return path, nil
}

func (h *DefaultHandler) reverseL4Header(header l4.L4Header) l4.L4Header {
	if header == nil {
		return nil
	}
	l4HeaderCopy := header.Copy()
	l4HeaderCopy.Reverse()
	return l4HeaderCopy
}

func (h *DefaultHandler) getPayload() common.Payload {
	if h.Payload == nil {
		return nil
	}
	return common.RawBytes(h.Payload)
}

// Prechecker can be used to customize how the SVC Resolution server reacts to
// certain packets, e.g., to log a message if the requested SVC is not the
// expected one.
type Prechecker interface {
	// Precheck evaluates if pkt satisfies a set of conditions, and returns an
	// error if the conditions are not met.
	//
	// Precheck implementations must panic if the packet's destination is not
	// an SVC address. Calling code should check this beforehand.
	Precheck(pkt *snet.SCIONPacket) error
}

var _ Prechecker = (*PrecheckSVC)(nil)

// PrecheckSVC can be used to check if a packet's destination address matches a
// specific SVC address. If the match fails, a callback is called.
type PrecheckSVC struct {
	// MatchSVC is the destination SVC address for which replies will be sent.
	//
	// Note that the default value for this field is the SCION Beacon Service
	// address (0x0000).
	MatchSVC addr.HostSVC
	// OnNonMatch is the callback to call if the destination SVC address of a
	// packet does not match (usually to set up some form of logging). If nil,
	// no callback is called.
	OnNonMatch func(pkt *snet.SCIONPacket)
}

func (p PrecheckSVC) Precheck(pkt *snet.SCIONPacket) error {
	requested := pkt.Destination.Host.(addr.HostSVC)
	if p.MatchSVC != pkt.Destination.Host.(addr.HostSVC) {
		if p.OnNonMatch != nil {
			p.OnNonMatch(pkt)
		}
		return common.NewBasicError("Requested SVC does not match local SVC address", nil,
			"local", p.MatchSVC, "requested", requested)
	}
	return nil
}
