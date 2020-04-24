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

package svc

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/svc/internal/ctxconn"
)

// Internal resolver errors. These are implementation details and can change,
// and calling code should not depend on them.
const (
	errNilPacket      common.ErrMsg = "packet is nil"
	errNilUnderlay    common.ErrMsg = "underlay is nil"
	errUnsupportedPld common.ErrMsg = "unsupported payload type"
	errRegistration   common.ErrMsg = "unable to open conn"
	errWrite          common.ErrMsg = "unable to write"
	errRead           common.ErrMsg = "unable to read"
	errDecode         common.ErrMsg = "decode failed"
	errBadPath        common.ErrMsg = "unable to parse return path"
)

// Resolver performs SVC address resolution.
type Resolver struct {
	// LocalIA is the local AS.
	LocalIA addr.IA
	// ConnFactory is used to open ports for SVC resolution messages.
	ConnFactory snet.PacketDispatcherService
	// LocalIP is the default L3 address for connections originating from this process.
	LocalIP net.IP
	// RoundTripper performs the request/reply exchange for SVC resolutions. If
	// nil, the default round tripper is used.
	RoundTripper RoundTripper
	// Payload is used for the data part of SVC requests.
	Payload []byte
}

// LookupSVC resolves the SVC address for the AS terminating the path.
func (r *Resolver) LookupSVC(ctx context.Context, p snet.Path, svc addr.HostSVC) (*Reply, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "svc.resolution")
	defer span.Finish()

	// FIXME(scrye): Assume registration is always instant for now. This,
	// however, should respect ctx.
	u := &net.UDPAddr{
		IP: r.LocalIP,
	}

	conn, port, err := r.ConnFactory.Register(ctx, r.LocalIA, u, addr.SvcNone)
	if err != nil {
		ext.Error.Set(span, true)
		return nil, common.NewBasicError(errRegistration, err)
	}

	requestPacket := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   r.LocalIA,
				Host: addr.HostFromIP(r.LocalIP),
			},
			Destination: snet.SCIONAddress{
				IA:   p.Destination(),
				Host: svc,
			},
			Path: p.Path(),
			L4Header: &l4.UDP{
				SrcPort: port,
			},
			Payload: common.RawBytes(r.Payload),
		},
	}
	reply, err := r.getRoundTripper().RoundTrip(ctx, conn, requestPacket, p.UnderlayNextHop())
	if err != nil {
		ext.Error.Set(span, true)
		return nil, err
	}
	return reply, nil
}

func (r *Resolver) getRoundTripper() RoundTripper {
	if r.RoundTripper == nil {
		return DefaultRoundTripper()
	}
	return r.RoundTripper
}

// RoundTripper does a single SVC resolution request/reply interaction over a
// connection, using the specified request packet and underlay address.
type RoundTripper interface {
	// RoundTrip performs the round trip interaction.
	RoundTrip(ctx context.Context, c snet.PacketConn, request *snet.Packet,
		u *net.UDPAddr) (*Reply, error)
}

// DefaultRoundTripper returns a basic implementation of the RoundTripper
// interface.
func DefaultRoundTripper() RoundTripper {
	return roundTripper{}
}

var _ RoundTripper = (*roundTripper)(nil)

type roundTripper struct{}

func (roundTripper) RoundTrip(ctx context.Context, c snet.PacketConn, pkt *snet.Packet,
	u *net.UDPAddr) (*Reply, error) {

	cancelF := ctxconn.CloseConnOnDone(ctx, c)
	defer cancelF()

	if pkt == nil {
		return nil, common.NewBasicError(errNilPacket, nil)
	}
	if u == nil {
		return nil, common.NewBasicError(errNilUnderlay, nil)
	}

	if err := c.WriteTo(pkt, u); err != nil {
		return nil, common.NewBasicError(errWrite, err)
	}

	var replyPacket snet.Packet
	var replyOv net.UDPAddr
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

	if replyPacket.Path != nil {
		if err := replyPacket.Path.Reverse(); err != nil {
			return nil, common.NewBasicError(errBadPath, err)
		}
		if err := replyPacket.Path.InitOffsets(); err != nil {
			return nil, common.NewBasicError(errBadPath, err)
		}
	}
	reply.ReturnPath = &path{
		spath:       replyPacket.Path,
		underlay:    &replyOv,
		destination: replyPacket.Source.IA,
	}
	return &reply, nil
}

type path struct {
	spath       *spath.Path
	underlay    *net.UDPAddr
	destination addr.IA
}

func (p *path) Fingerprint() snet.PathFingerprint {
	return ""
}

func (p *path) UnderlayNextHop() *net.UDPAddr {
	return p.underlay
}

func (p *path) Path() *spath.Path {
	return p.spath
}

func (p *path) Interfaces() []snet.PathInterface {
	return nil
}

func (p *path) Destination() addr.IA {
	return p.destination
}

func (p *path) MTU() uint16 {
	return 0
}

func (p *path) Expiry() time.Time {
	return time.Time{}
}

func (p *path) Copy() snet.Path {
	if p == nil {
		return nil
	}
	return &path{
		spath:       p.spath.Copy(),
		underlay:    snet.CopyUDPAddr(p.underlay),
		destination: p.destination,
	}
}
