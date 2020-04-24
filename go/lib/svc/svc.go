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

// Package svc implements support for SVC Resolution.
package svc

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

const ErrHandler common.ErrMsg = "Unable to handle SVC request"

// Result is used to inform Handler users on the outcome of handler execution.
type Result int

const (
	// Error means that the handler experience an error during processing.
	Error Result = iota
	// Handled means that the handler completed successfully.
	Handled
	// Forward means that the packet should be forwarded to the application.
	Forward
)

// NewResolverPacketDispatcher creates a dispatcher service that returns
// sockets with built-in SVC address resolution capabilities.
//
// RequestHandler results during connection read operations are handled in the
// following way:
//  - on error result, the error is sent back to the reader
//  - on forwarding result, the packet is sent back to the app for processing.
//  - on handled result, the packet is discarded after processing, and a new
//  read is attempted from the connection, and the entire decision process
//  repeats.
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

func (d *ResolverPacketDispatcher) Register(ctx context.Context, ia addr.IA,
	registration *net.UDPAddr, svc addr.HostSVC) (snet.PacketConn, uint16, error) {

	c, port, err := d.dispService.Register(ctx, ia, registration, svc)
	if err != nil {
		return nil, 0, err
	}
	packetConn := &resolverPacketConn{
		PacketConn: c,
		source: snet.SCIONAddress{
			IA:   ia,
			Host: addr.HostFromIP(registration.IP),
		},
		handler: d.handler,
	}
	return packetConn, port, err
}

// resolverPacketConn redirects SVC destination packets to SVC resolution
// handler logic.
type resolverPacketConn struct {
	// PacketConn is the conn to receive and send packets.
	snet.PacketConn
	// source contains the address from which packets should be sent.
	source snet.SCIONAddress
	// handler handles packets for SVC destinations.
	handler RequestHandler
}

func (c *resolverPacketConn) ReadFrom(pkt *snet.Packet, ov *net.UDPAddr) error {
	for {
		if err := c.PacketConn.ReadFrom(pkt, ov); err != nil {
			return err
		}

		// XXX(scrye): destination address is guaranteed to not be nil
		svc, ok := pkt.Destination.Host.(addr.HostSVC)
		if !ok {
			// Normal packet, return to caller because data is already parsed and ready
			return nil
		}

		// Multicasts do not trigger SVC resolution logic
		if svc.IsMulticast() {
			return nil
		}

		// XXX(scrye): This might block, causing the read to wait for the
		// write to go through. The solution would be to run the logic in a
		// goroutine, but because UDP writes rarely block, the current
		// solution should be good enough for now.
		r := &Request{
			Conn:     c.PacketConn,
			Source:   c.source,
			Packet:   pkt,
			Underlay: ov,
		}
		switch result, err := c.handler.Handle(r); result {
		case Error:
			return common.NewBasicError(ErrHandler, err)
		case Forward:
			return nil
		default:
			// Message handled, read new packet
		}
	}
}

// RequestHandler handles SCION packets with SVC destination addresses.
type RequestHandler interface {
	// Handle replies to SCION packets with SVC destinations coming from the
	// specified underlay address.
	//
	// Handle implementantions might panic if the destination is not an SVC
	// address, so callers should perform the check beforehand.
	Handle(*Request) (Result, error)
}

type Request struct {
	// Source is the override value for the source address of the reply packet.
	Source snet.SCIONAddress
	// Conn is the connection to send the reply on. Conn must not be nil.
	Conn     snet.PacketConn
	Packet   *snet.Packet
	Underlay *net.UDPAddr
}

var _ RequestHandler = (*BaseHandler)(nil)

// BaseHandler reverses a SCION packet, replaces the source address with the
// one in the struct and then sends the message on the connection.
type BaseHandler struct {
	// Message is the payload data to send in the reply. Nil and zero-length
	// payloads are supported.
	Message []byte
}

func (h *BaseHandler) Handle(request *Request) (Result, error) {
	path, err := h.reversePath(request.Packet.Path)
	if err != nil {
		return Error, err
	}
	l4header := h.reverseL4Header(request.Packet.L4Header)
	replyPacket := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: request.Packet.Source,
			Source:      request.Source,
			Path:        path,
			L4Header:    l4header,
			Payload:     h.getPayload(),
		},
	}
	err = request.Conn.WriteTo(replyPacket, request.Underlay)
	if err != nil {
		return Error, err
	}
	return Handled, nil
}

func (h *BaseHandler) reversePath(path *spath.Path) (*spath.Path, error) {
	if !path.IsEmpty() {
		// Reverse copy to not modify input packet
		path = path.Copy()
		if err := path.Reverse(); err != nil {
			return path, err
		}
	}
	return path, nil
}

func (h *BaseHandler) reverseL4Header(header l4.L4Header) l4.L4Header {
	if header == nil {
		return nil
	}
	l4HeaderCopy := header.Copy()
	l4HeaderCopy.Reverse()
	return l4HeaderCopy
}

func (h *BaseHandler) getPayload() common.Payload {
	if h.Message == nil {
		return nil
	}
	return common.RawBytes(h.Message)
}
