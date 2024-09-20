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
	"context"
	"net"
	"net/netip"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/svc/internal/ctxconn"
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
)

// For now, the request payload does not need to be dynamic. We initialize it
// once on application start.
var requestPayload []byte

func init() {
	var err error
	if requestPayload, err = proto.Marshal(&cppb.ServiceResolutionRequest{}); err != nil {
		panic(err)
	}
}

// Resolver performs SVC address resolution.
type Resolver struct {
	Network snet.Network
	// LocalIA is the local AS.
	LocalIA addr.IA
	// LocalIP is the default L3 address for connections originating from this process.
	LocalIP net.IP
	// RoundTripper performs the request/reply exchange for SVC resolutions. If
	// nil, the default round tripper is used.
	RoundTripper RoundTripper
}

// LookupSVC resolves the SVC address for the AS terminating the path.
func (r *Resolver) LookupSVC(ctx context.Context, p snet.Path, svc addr.SVC) (*Reply, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "svc.resolution")
	span.SetTag("svc", svc.String())
	span.SetTag("isd_as", p.Destination().String())
	defer span.Finish()

	u := &net.UDPAddr{
		IP: r.LocalIP,
	}
	localIP, ok := netip.AddrFromSlice(r.LocalIP)
	if !ok {
		return nil, serrors.New("invalid local IP", "ip", r.LocalIP)
	}

	conn, err := r.Network.OpenRaw(ctx, u)
	if err != nil {
		ext.Error.Set(span, true)
		return nil, serrors.JoinNoStack(errRegistration, err)
	}
	cancelF := ctxconn.CloseConnOnDone(ctx, conn)
	defer func() {
		if err := cancelF(); err != nil {
			log.Info("Error closing conn", "err", err)
		}
	}()

	requestPacket := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   r.LocalIA,
				Host: addr.HostIP(localIP),
			},
			Destination: snet.SCIONAddress{
				IA:   p.Destination(),
				Host: addr.HostSVC(svc),
			},
			Path: p.Dataplane(),
			Payload: snet.UDPPayload{
				SrcPort: uint16(conn.LocalAddr().(*net.UDPAddr).Port),
				Payload: requestPayload,
			},
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

	if pkt == nil {
		return nil, errNilPacket
	}
	if u == nil {
		return nil, errNilUnderlay
	}

	if err := c.WriteTo(pkt, u); err != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		return nil, serrors.JoinNoStack(errWrite, err)
	}

	var replyPacket snet.Packet
	var replyOv net.UDPAddr
	if err := c.ReadFrom(&replyPacket, &replyOv); err != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		return nil, serrors.JoinNoStack(errRead, err)
	}
	udp, ok := replyPacket.Payload.(snet.UDPPayload)
	if !ok {
		return nil, serrors.JoinNoStack(errUnsupportedPld, nil,
			"type", common.TypeOf(replyPacket.Payload))

	}
	var reply Reply
	if err := reply.Unmarshal(udp.Payload); err != nil {
		return nil, serrors.JoinNoStack(errDecode, err)
	}

	rpath, ok := replyPacket.Path.(snet.RawPath)
	if !ok {
		return nil, serrors.New("unexpected path", "type", common.TypeOf(replyPacket.Path))
	}
	replyPath, err := snet.DefaultReplyPather{}.ReplyPath(rpath)
	if err != nil {
		return nil, serrors.Wrap("creating reply path", err)
	}
	reply.ReturnPath = &path{
		dataplane:   replyPath,
		underlay:    &replyOv,
		source:      replyPacket.Destination.IA,
		destination: replyPacket.Source.IA,
	}
	return &reply, nil
}

type path struct {
	dataplane   snet.DataplanePath
	underlay    *net.UDPAddr
	destination addr.IA
	source      addr.IA
}

func (p *path) UnderlayNextHop() *net.UDPAddr {
	return p.underlay
}

func (p *path) Dataplane() snet.DataplanePath {
	return p.dataplane
}

func (p *path) Interfaces() []snet.PathInterface {
	return nil
}

func (p *path) Source() addr.IA {
	return p.source
}

func (p *path) Destination() addr.IA {
	return p.destination
}

func (p *path) Metadata() *snet.PathMetadata {
	return nil
}

func (p *path) Copy() snet.Path {
	if p == nil {
		return nil
	}
	return &path{
		dataplane:   p.dataplane,
		underlay:    snet.CopyUDPAddr(p.underlay),
		source:      p.source,
		destination: p.destination,
	}
}
