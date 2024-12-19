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

package appnet

import (
	"context"
	"fmt"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/svc"
)

// Resolver performs SVC resolution for a remote AS, thus converting an anycast
// SVC address to a unicast IP/UDP one.
type Resolver interface {
	// LookupSVC resolves the SVC address for the AS terminating the path.
	LookupSVC(ctx context.Context, path snet.Path, svc addr.SVC) (*svc.Reply, error)
}

// AddressRewriter is used to compute paths and replace SVC destinations with
// unicast addresses.
type AddressRewriter struct {
	// Router obtains path information to fill in address paths, if they are
	// required and missing.
	Router snet.Router
	// SVCRouter builds underlay addresses for intra-AS SVC traffic, based on
	// information found in the topology.
	SVCRouter SVCResolver
	// Resolver performs SVC resolution if enabled.
	Resolver Resolver
}

// RedirectToQUIC takes an address and adds a path (if one does not already
// exist but is required), and replaces SVC destinations with QUIC unicast
// ones, if possible.
//
// If the address is already unicast, no redirection to QUIC is attempted.
func (r AddressRewriter) RedirectToQUIC(ctx context.Context,
	address net.Addr) (net.Addr, error) {

	switch a := address.(type) {
	case *snet.UDPAddr:
		return a, nil
	case *snet.SVCAddr:
		fa, err := r.buildFullAddress(ctx, a)
		if err != nil {
			return nil, err
		}

		path, err := fa.GetPath()
		if err != nil {
			return nil, serrors.Wrap("bad path", err)
		}

		// During One-Hop Path operation, use SVC resolution to also bootstrap the path.
		p, u, err := r.resolveSVC(ctx, path, fa.SVC)
		if err != nil {
			return a, err
		}

		ret := &snet.UDPAddr{IA: fa.IA, Path: p.Dataplane(), NextHop: fa.NextHop, Host: u}
		return ret, nil
	}

	return nil, serrors.New("address type not supported",
		"addr", fmt.Sprintf("%v(%T)", address, address))
}

// buildFullAddress checks that a is a well-formed address (all fields set,
// non-nil, only supported protocols). If the path is missing, the path and
// next-hop are added by performing a routing lookup. The returned address is
// always a copy, and the input address is guaranteed to not change.
func (r AddressRewriter) buildFullAddress(ctx context.Context,
	s *snet.SVCAddr) (*snet.SVCAddr, error) {

	if _, isEmpty := s.Path.(path.Empty); !isEmpty && s.Path != nil {
		ret := &snet.SVCAddr{
			IA:      s.IA,
			Path:    s.Path,
			NextHop: snet.CopyUDPAddr(s.NextHop),
			SVC:     s.SVC,
		}
		return ret, nil
	}

	ret := &snet.SVCAddr{IA: s.IA, SVC: s.SVC}
	p, err := r.Router.Route(ctx, s.IA)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, serrors.New("no path found", "isd_as", s.IA)
	}

	ret.Path = p.Dataplane()
	ret.NextHop = p.UnderlayNextHop()

	// SVC addresses in the local AS get resolved via topology lookup
	if len(p.Metadata().Interfaces) == 0 { //when local AS
		ov, err := r.SVCRouter.GetUnderlay(s.SVC)
		if err != nil {
			return nil, serrors.Wrap("Unable to resolve underlay", err)
		}
		ret.NextHop = ov
		ret.Path = path.Empty{}
	}

	return ret, nil
}

// resolveSVC performs SVC resolution and returns an UDP/IP address.
// If the address does not have an SVC destination, it is returned
// unchanged. If address is not a well-formed application address (all fields
// set, non-nil, supported protocols), the function's behavior is undefined.
// The returned path is the path contained in the reply; the path can be used
// to talk to the remote AS after One-Hop Path construction.
func (r AddressRewriter) resolveSVC(ctx context.Context, p snet.Path,
	s addr.SVC) (snet.Path, *net.UDPAddr, error) {
	logger := log.FromCtx(ctx)

	logger.Debug("Sending SVC resolution request", "isd_as", p.Destination(), "svc", s)

	reply, err := r.Resolver.LookupSVC(ctx, p, s)
	if err != nil {
		logger.Debug("SVC resolution failed", "err", err)
		return nil, nil, err
	}

	logger.Debug("SVC resolution successful", "reply", reply)
	u, err := parseReply(reply)
	if err != nil {
		return nil, nil, err
	}
	return reply.ReturnPath, u, nil
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

// SVCResolver is used to construct underlay information for SVC servers
// running in the local AS.
type SVCResolver interface {
	// GetUnderlay returns the underlay address of a SVC server of the specified
	// type. When multiple servers are available, the choice is random. If no
	// servers are available an error should be returned.
	GetUnderlay(svc addr.SVC) (*net.UDPAddr, error)
}
