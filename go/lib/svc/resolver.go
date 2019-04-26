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

package svc

import (
	"bytes"
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/svc/internal/ctxconn"
)

// Internal resolver errors. These are implementation details and can change,
// and calling code should not depend on them.
const (
	errNilPacket      = "packet is nil"
	errNilOverlay     = "overlay is nil"
	errUnsupportedPld = "unsupported payload type"
	errRegistration   = "unable to open conn"
	errWrite          = "unable to write"
	errRead           = "unable to read"
	errDecode         = "decode failed"
)

// Resolver performs SVC address resolution.
type Resolver struct {
	// LocalIA is the local AS.
	LocalIA addr.IA
	// ConnFactory is used to open ports for SVC resolution messages.
	ConnFactory snet.PacketDispatcherService
	// Machine is used to derive addressing information for local conns.
	Machine snet.LocalMachine
	// RoundTripper performs the request/reply exchange for SVC resolutions. If
	// nil, the default round tripper is used.
	RoundTripper RoundTripper
}

// LookupSVC resolves the SVC address for the AS terminating the path.
func (r *Resolver) LookupSVC(ctx context.Context, p snet.Path, svc addr.HostSVC) (*Reply, error) {
	// FIXME(scrye): Assume registration is always instant for now. This,
	// however, should respect ctx.
	conn, port, err := r.ConnFactory.RegisterTimeout(r.LocalIA, r.Machine.AppAddress(),
		nil, addr.SvcNone, 0)
	if err != nil {
		return nil, common.NewBasicError(errRegistration, err)
	}
	defer conn.Close()

	requestPacket := &snet.SCIONPacket{
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Source: snet.SCIONAddress{
				IA:   r.LocalIA,
				Host: r.Machine.AppAddress().L3,
			},
			Destination: snet.SCIONAddress{
				IA:   p.Destination(),
				Host: svc,
			},
			Path: p.Path(),
			L4Header: &l4.UDP{
				SrcPort: port,
			},
			// FIXME(scrye): Add a dummy payload, because nil payloads are not supported.
			Payload: common.RawBytes{0},
		},
	}
	return r.getRoundTripper().RoundTrip(ctx, conn, requestPacket, p.OverlayNextHop())
}

func (r *Resolver) getRoundTripper() RoundTripper {
	if r.RoundTripper == nil {
		return DefaultRoundTripper()
	}
	return r.RoundTripper
}

// RoundTripper does a single SVC resolution request/reply interaction over a
// connection, using the specified request packet and overlay address.
type RoundTripper interface {
	// RoundTrip performs the round trip interaction.
	RoundTrip(ctx context.Context, c snet.PacketConn, request *snet.SCIONPacket,
		ov *overlay.OverlayAddr) (*Reply, error)
}

// DefaultRoundTripper returns a basic implementation of the RoundTripper
// interface.
func DefaultRoundTripper() RoundTripper {
	return roundTripper{}
}

var _ RoundTripper = (*roundTripper)(nil)

type roundTripper struct{}

func (roundTripper) RoundTrip(ctx context.Context, c snet.PacketConn, pkt *snet.SCIONPacket,
	ov *overlay.OverlayAddr) (*Reply, error) {

	if pkt == nil {
		return nil, common.NewBasicError(errNilPacket, nil)
	}
	if ov == nil {
		return nil, common.NewBasicError(errNilOverlay, nil)
	}

	cancelF := ctxconn.CloseConnOnDone(ctx, c)
	defer cancelF()

	if err := c.WriteTo(pkt, ov); err != nil {
		return nil, common.NewBasicError(errWrite, err)
	}

	var replyPacket snet.SCIONPacket
	var replyOv overlay.OverlayAddr
	if err := c.ReadFrom(&replyPacket, &replyOv); err != nil {
		return nil, common.NewBasicError(errRead, err)
	}
	b, ok := replyPacket.Payload.(common.RawBytes)
	if !ok {
		return nil, common.NewBasicError(errUnsupportedPld, nil, "payload", replyPacket.Payload)
	}
	var reply Reply
	if err := reply.DecodeFrom(bytes.NewBuffer([]byte(b))); err != nil {
		return nil, common.NewBasicError(errDecode, err)
	}
	return &reply, nil
}
