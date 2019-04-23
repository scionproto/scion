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
)

// Resolver performs SVC address resolution.
type Resolver struct {
	// Router is used to compute paths to remote ASes.
	Router snet.Router
	// ConnFactory is used to open ports for SVC resolution messages.
	ConnFactory snet.PacketDispatcherService
	// Machine is used to derive addressing information for local conns.
	Machine snet.LocalMachine
	// RoundTripper performs the request/reply exchange for SVC resolutions. If
	// nil, the default round tripper is used.
	RoundTripper RoundTripper
}

// LookupSVC resolves SVC addresses for a remote AS.
func (r *Resolver) LookupSVC(ctx context.Context, ia addr.IA, svc addr.HostSVC) (*Reply, error) {
	path, err := r.Router.Route(ctx, ia)
	if err != nil {
		return nil, err
	}

	conn, port, err := r.ConnFactory.RegisterTimeout(ia, r.Machine.AppAddress(),
		r.Machine.BindAddress(), addr.SvcNone, 0)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	requestPacket := &snet.SCIONPacket{
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Source: snet.SCIONAddress{
				IA:   r.Router.LocalIA(),
				Host: r.Machine.AppAddress().L3,
			},
			Destination: snet.SCIONAddress{
				IA:   ia,
				Host: svc,
			},
			Path: path.Path(),
			L4Header: &l4.UDP{
				SrcPort: port,
			},
		},
	}
	return r.getRoundTripper().RoundTrip(ctx, conn, requestPacket, path.OverlayNextHop())
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
		return nil, err
	}

	var replyPacket snet.SCIONPacket
	var replyOv overlay.OverlayAddr
	if err := c.ReadFrom(&replyPacket, &replyOv); err != nil {
		return nil, err
	}
	b, ok := replyPacket.Payload.(common.RawBytes)
	if !ok {
		return nil, common.NewBasicError(errUnsupportedPld, nil, "payload", replyPacket.Payload)
	}
	var reply Reply
	if err := reply.DecodeFrom(bytes.NewBuffer([]byte(b))); err != nil {
		return nil, err
	}
	return &reply, nil
}
