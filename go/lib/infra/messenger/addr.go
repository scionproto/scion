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

package messenger

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/svc"
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
func (r AddressRewriter) RedirectToQUIC(ctx context.Context, a net.Addr) (net.Addr, bool, error) {
	// FIXME(scrye): This is not legitimate use. It's only included for
	// compatibility with older unit tests. See
	// https://github.com/scionproto/scion/issues/2611.
	if a == nil {
		return nil, false, nil
	}
	fullAddress, err := r.buildFullAddress(ctx, a)
	if err != nil {
		return nil, false, err
	}
	path, err := fullAddress.GetPath()
	if err != nil {
		return nil, false, common.NewBasicError("bad path", err)
	}
	var quicRedirect bool
	fullAddress.Host, quicRedirect, err = r.resolveIfSVC(ctx, path, fullAddress.Host)
	return fullAddress, quicRedirect, err
}

// buildFullAddress checks that a is a well-formed address (all fields set,
// non-nil, only supported protocols). If the path is missing, the path and
// next-hop are added by performing a routing lookup. The returned address is
// always a copy, and the input address is guaranteed to not change.
func (r AddressRewriter) buildFullAddress(ctx context.Context, a net.Addr) (*snet.Addr, error) {
	snetAddr, ok := a.(*snet.Addr)
	if !ok {
		return nil, common.NewBasicError("address type not supported", nil, "addr", a)
	}
	if snetAddr.Host == nil {
		return nil, common.NewBasicError("host address not specified", nil, "addr", snetAddr)
	}
	if snetAddr.Host.L3 == nil {
		return nil, common.NewBasicError("host address missing L3 address", nil, "addr", snetAddr)
	}
	if snetAddr.Host.L4 == nil {
		return nil, common.NewBasicError("host address missing L4 address", nil, "addr", snetAddr)
	}
	if t := snetAddr.Host.L3.Type(); !addr.HostTypeCheck(t) {
		return nil, common.NewBasicError("host address L3 address not supported", nil, "type", t)
	}
	if t := snetAddr.Host.L4.Type(); t != common.L4UDP {
		return nil, common.NewBasicError("host address L4 address not supported", nil, "type", t)
	}
	newAddr := snetAddr.Copy()

	if newAddr.Path == nil {
		p, err := r.Router.Route(ctx, newAddr.IA)
		if err != nil {
			return nil, err
		}
		newAddr.Path = p.Path()
		newAddr.NextHop = p.OverlayNextHop()
	}
	return newAddr, nil
}

// resolveIfSvc performs SVC resolution and returns an UDP/IP address if the
// input address is an SVC destination. If the UDP/IP address is for a
// QUIC-compatible server, the returned boolean value is set to true. If the
// address does not have an SVC destination, it is returned unchanged. If
// address is not a well-formed application address (all fields set, non-nil,
// supported protocols), the function's behavior is undefined. The returned
// address is always a copy.
func (r AddressRewriter) resolveIfSVC(ctx context.Context, p snet.Path,
	address *addr.AppAddr) (*addr.AppAddr, bool, error) {

	svcAddress, ok := address.L3.(addr.HostSVC)
	if !ok {
		return address.Copy(), false, nil
	}
	if r.SVCResolutionFraction <= 0.0 {
		return address.Copy(), false, nil
	}

	if r.SVCResolutionFraction < 1.0 {
		var cancelF context.CancelFunc
		ctx, cancelF = r.resolutionCtx(ctx)
		defer cancelF()
	}
	logger := log.FromCtx(ctx)
	logger.Trace("Sending SVC resolution request", "ia", p.Destination(), "svc", svcAddress,
		"svcResFraction", r.SVCResolutionFraction)
	reply, err := r.Resolver.LookupSVC(ctx, p, svcAddress)
	if err != nil {
		if r.SVCResolutionFraction < 1.0 {
			// SVC resolution failed but we allow legacy behavior and have some
			// fraction of the timeout left for data transfers, so return
			// address with SVC destination still set
			logger.Trace("SVC resolution failed, falling back to legacy mode", "err", err)
			return address.Copy(), false, nil
		}
		// Legacy behavior is disallowed, so propagate a hard failure back to the app.
		logger.Trace("SVC resolution failed and legacy mode disabled", "err", err)
		return nil, false, err
	}
	logger.Trace("SVC resolution successful", "reply", reply)

	appAddr, err := parseReply(reply)
	if err != nil {
		return nil, false, err
	}
	return appAddr, true, nil
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
func parseReply(reply *svc.Reply) (*addr.AppAddr, error) {
	if reply == nil {
		return nil, common.NewBasicError("nil reply", nil)
	}
	if reply.Transports == nil {
		return nil, common.NewBasicError("empty reply", nil)
	}
	addressStr, ok := reply.Transports[svc.QUIC]
	if !ok {
		return nil, common.NewBasicError("QUIC server address not found", nil)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addressStr)
	if err != nil {
		return nil, common.NewBasicError("Unable to parse address", err)
	}
	return &addr.AppAddr{
		L3: addr.HostFromIP(udpAddr.IP),
		L4: addr.NewL4UDPInfo(uint16(udpAddr.Port)),
	}, nil
}

// BuildReply constructs a reply from an application address. If the
// application address is not well formed (has L3, has L4, UDP/IP protocols),
// the returned reply is non-nil and empty.
func BuildReply(address *addr.AppAddr) *svc.Reply {
	if address == nil || address.L3 == nil || address.L4 == nil {
		return &svc.Reply{}
	}
	if address.L4.Type() != common.L4UDP {
		return &svc.Reply{}
	}
	port := fmt.Sprintf("%v", address.L4.Port())

	var ip string
	switch t := address.L3.(type) {
	case addr.HostIPv4:
		ip = t.String()
	case addr.HostIPv6:
		ip = t.String()
	default:
		return &svc.Reply{}
	}
	return &svc.Reply{
		Transports: map[svc.Transport]string{
			svc.UDP: net.JoinHostPort(ip, port),
		},
	}
}
