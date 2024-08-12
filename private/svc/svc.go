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
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
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

// ResolverPacketConn redirects SVC destination packets to SVC resolution
// handler logic.
type ResolverPacketConn struct {
	// PacketConn is the conn to receive and send packets.
	snet.PacketConn
	// Source contains the address from which packets should be sent.
	Source snet.SCIONAddress
	// Handler handles packets for SVC destinations.
	Handler RequestHandler
}

func (c *ResolverPacketConn) ReadFrom(pkt *snet.Packet, ov *net.UDPAddr) error {
	for {
		if err := c.PacketConn.ReadFrom(pkt, ov); err != nil {
			return err
		}
		// XXX(scrye): destination address is guaranteed to not be nil
		if pkt.Destination.Host.Type() != addr.HostTypeSVC {
			// Normal packet, return to caller because data is already parsed and ready
			return nil
		}
		// XXX(scrye): This might block, causing the read to wait for the
		// write to go through. The solution would be to run the logic in a
		// goroutine, but because UDP writes rarely block, the current
		// solution should be good enough for now.
		r := &Request{
			Conn:     c.PacketConn,
			Source:   c.Source,
			Packet:   pkt,
			Underlay: ov,
		}
		switch result, err := c.Handler.Handle(r); result {
		case Error:
			// We do not propagate error to caller, to avoid the connection fails,
			// e.g., within QUIC layer.
			log.Error("Error handling SVC request", "err", err)
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
	udp, ok := request.Packet.Payload.(snet.UDPPayload)
	if !ok {
		return Error, serrors.New("invalid payload in request",
			"expected", "UDP", "type", common.TypeOf(request.Packet.Payload))
	}
	replyPacket := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: request.Packet.Source,
			Source:      request.Source,
			Path:        path,
			Payload: snet.UDPPayload{
				DstPort: udp.SrcPort,
				SrcPort: udp.DstPort,
				Payload: h.Message,
			},
		},
	}

	err = request.Conn.WriteTo(replyPacket, request.Underlay)
	if err != nil {
		return Error, err
	}
	return Handled, nil
}

func (h *BaseHandler) reversePath(path snet.DataplanePath) (snet.DataplanePath, error) {
	rpath, ok := path.(snet.RawPath)
	if !ok {
		return nil, serrors.New("unexpected path", "type", common.TypeOf(path))
	}
	replyPath, err := snet.DefaultReplyPather{}.ReplyPath(rpath)
	if err != nil {
		return nil, serrors.Wrap("creating reply path", err)
	}
	return replyPath, nil
}
