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

package messenger

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/lib/topology"
)

// Resolver performs SVC resolution for a remote AS, thus converting an anycast
// SVC address to a unicast IP/UDP one.
type Resolver interface {
	// LookupSVC resolves the SVC address for the AS terminating the path.
	LookupSVC(ctx context.Context, path snet.Path, svc addr.HostSVC) (*svc.Reply, error)
}

// AddressRewriter is used to compute paths and replace SVC destinations with
// unicast addresses.
type AddressRewriter struct {
	// Router obtains path information to fill in address paths, if they are
	// required and missing.
	Router snet.Router
	// SVCRouter builds underlay addresses for intra-AS SVC traffic, based on
	// information found in the topology.
	SVCRouter LocalSVCRouter
	// Resolver performs SVC resolution if enabled.
	Resolver Resolver
	// SVCResolutionFraction enables SVC resolution for traffic to SVC
	// destinations in a way that is also compatible with control plane servers
	// that do not implement the SVC Resolution Mechanism. The value represents
	// the percentage of time, out of the total available context timeout,
	// spent attempting to perform SVC resolution. If SVCResolutionFraction is
	// 0 or less, SVC resolution is never attempted. If it is between 0 and 1,
	// the remaining context timeout is multiplied by the value, and that
	// amount of time is spent waiting for an SVC resolution reply from the
	// server. If this times out, the data packet is sent with an SVC
	// destination. If the value is 1 or more, then legacy behavior is
	// disabled, and data packets are never sent to SVC destinations unless the
	// resolution step is successful.
	SVCResolutionFraction float64
}

// RedirectToQUIC takes an address and adds a path (if one does not already
// exist but is required), and replaces SVC destinations with QUIC unicast
// ones, if possible.
//
// The returned boolean value is set to true if the remote server is
// QUIC-compatible and we have successfully discovered its address.
//
// If the address is already unicast, no redirection to QUIC is attempted.
func (r AddressRewriter) RedirectToQUIC(ctx context.Context,
	address net.Addr) (net.Addr, bool, error) {
	logger := log.FromCtx(ctx)

	// FIXME(scrye): This is not legitimate use. It's only included for
	// compatibility with older unit tests. See
	// https://github.com/scionproto/scion/issues/2611.
	if address == nil {
		return address, false, nil
	}

	switch a := address.(type) {
	case *snet.UDPAddr:
		return a, false, nil
	case *snet.SVCAddr:
		fa, err := r.buildFullAddress(ctx, a)
		if err != nil {
			return nil, false, err
		}
		if r.SVCResolutionFraction <= 0.0 {
			return fa, false, nil
		}

		path, err := fa.GetPath()
		if err != nil {
			return nil, false, common.NewBasicError("bad path", err)
		}

		// During One-Hop Path operation, use SVC resolution to also bootstrap the path.
		p, u, quicRedirect, err := r.resolveSVC(ctx, path, fa.SVC)
		if err != nil {
			if r.SVCResolutionFraction < 1.0 {
				// SVC resolution failed but we allow legacy behavior and have some
				// fraction of the timeout left for data transfers, so return
				// address with SVC destination still set
				logger.Trace("Falling back to legacy mode, ignore error", "err", err)
				return fa, false, nil
			}
			return a, false, err
		}

		ret := &snet.UDPAddr{IA: fa.IA, Path: p.Path(), NextHop: fa.NextHop, Host: u}
		return ret, quicRedirect, err
	}

	return nil, false, common.NewBasicError("address type not supported", nil,
		"addr", fmt.Sprintf("%v(%T)", address, address))
}

// buildFullAddress checks that a is a well-formed address (all fields set,
// non-nil, only supported protocols). If the path is missing, the path and
// next-hop are added by performing a routing lookup. The returned address is
// always a copy, and the input address is guaranteed to not change.
func (r AddressRewriter) buildFullAddress(ctx context.Context,
	s *snet.SVCAddr) (*snet.SVCAddr, error) {

	if s.Path != nil {
		ret := &snet.SVCAddr{
			IA:      s.IA,
			Path:    s.Path.Copy(),
			NextHop: snet.CopyUDPAddr(s.NextHop),
			SVC:     s.SVC,
		}
		log.Trace("[Acceptance]", "underlay", ret.NextHop)
		return ret, nil
	}

	ret := &snet.SVCAddr{IA: s.IA, SVC: s.SVC}
	p, err := r.Router.Route(ctx, s.IA)
	if err != nil {
		return nil, err
	}

	ret.Path = p.Path()
	ret.NextHop = p.UnderlayNextHop()
	defer func() {
		log.Trace("[Acceptance]", "underlay", ret.NextHop)
	}()

	// SVC addresses in the local AS get resolved via topology lookup
	if p.Fingerprint() == "" { //when local AS
		ov, err := r.SVCRouter.GetUnderlay(s.SVC)
		if err != nil {
			return nil, common.NewBasicError("Unable to resolve underlay", err)
		}
		ret.NextHop = ov
	}

	return ret, nil
}

// resolveSVC performs SVC resolution and returns an UDP/IP address. If the UDP/IP
// address is for a QUIC-compatible server, the returned boolean value is set
// to true. If the address does not have an SVC destination, it is returned
// unchanged. If address is not a well-formed application address (all fields
// set, non-nil, supported protocols), the function's behavior is undefined.
// The returned path is the path contained in the reply; the path can be used
// to talk to the remote AS after One-Hop Path construction.
func (r AddressRewriter) resolveSVC(ctx context.Context, p snet.Path,
	s addr.HostSVC) (snet.Path, *net.UDPAddr, bool, error) {
	logger := log.FromCtx(ctx)
	if r.SVCResolutionFraction < 1.0 {
		var cancelF context.CancelFunc
		ctx, cancelF = r.resolutionCtx(ctx)
		defer cancelF()
	}

	logger.Trace("Sending SVC resolution request", "ia", p.Destination(), "svc", s,
		"svcResFraction", r.SVCResolutionFraction)

	reply, err := r.Resolver.LookupSVC(ctx, p, s)
	if err != nil {
		logger.Trace("SVC resolution failed", "err", err)
		return nil, nil, false, err
	}

	logger.Trace("SVC resolution successful", "reply", reply)
	u, err := parseReply(reply)
	if err != nil {
		return nil, nil, false, err
	}
	return reply.ReturnPath, u, true, nil
}

func (r AddressRewriter) resolutionCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}

	timeout := deadline.Sub(time.Now())
	timeout = time.Duration(float64(timeout) * r.SVCResolutionFraction)
	return context.WithTimeout(ctx, timeout)
}

// parseReply searches for a QUIC server on the remote address. If one is not
// found, an error is returned.
func parseReply(reply *svc.Reply) (*net.UDPAddr, error) {
	if reply == nil {
		return nil, serrors.New("nil reply")
	}
	if reply.Transports == nil {
		return nil, serrors.New("empty reply")
	}
	addressStr, ok := reply.Transports[svc.QUIC]
	if !ok {
		return nil, serrors.New("QUIC server address not found")
	}
	return net.ResolveUDPAddr("udp", addressStr)
}

// LocalSVCRouter is used to construct underlay information for SVC servers
// running in the local AS.
type LocalSVCRouter interface {
	// GetUnderlay returns the underlay address of a SVC server of the specified
	// type. When multiple servers are available, the choice is random.
	GetUnderlay(svc addr.HostSVC) (*net.UDPAddr, error)
}

// NewSVCRouter build a SVC router backed by topology information from the
// specified provider.
func NewSVCRouter(tp topology.Provider) LocalSVCRouter {
	return &baseSVCRouter{
		topology: tp,
	}
}

type baseSVCRouter struct {
	topology topology.Provider
}

func (r *baseSVCRouter) GetUnderlay(svc addr.HostSVC) (*net.UDPAddr, error) {
	return r.topology.Get().UnderlayAnycast(svc)
}
