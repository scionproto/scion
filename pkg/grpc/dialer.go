// Copyright 2020 Anapaya Systems
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

package grpc

import (
	"context"
	"net"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

// Dialer creates a gRPC client connection to the given target.
type Dialer interface {
	// DialContext creates a client connection to the given target.
	Dial(context.Context, net.Addr) (*grpc.ClientConn, error)
}

// SimpleDialer implements a wrapper around grpc.DialContext that implements the
// dialer interface. It simply uses the string of the address to dial.
type SimpleDialer struct{}

// Dial creates a new client and blocks until con is in state ready.
func (SimpleDialer) Dial(ctx context.Context, address net.Addr) (*grpc.ClientConn, error) {
	target := address.String()

	con, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", target)
		}),
		UnaryClientInterceptor(),
		StreamClientInterceptor(),
	)
	if err != nil {
		return nil, err
	}

	// Manually wait until the connection is ready simulating the use of grpc.WithBlock()
	// even though this is no longer recommended
	// (see https://github.com/grpc/grpc-go/blob/master/Documentation/anti-patterns.md)
	// to maintain compatibility until we remove gRPC completely
	// (see https://github.com/scionproto/scion/issues/4434).
	for {
		s := con.GetState()
		if s == connectivity.Ready {
			break
		}
		if !con.WaitForStateChange(ctx, s) {
			_ = con.Close()
			return nil, ctx.Err() // context timeout or cancel
		}
	}
	return con, nil
}

// XXX(roosd):
//
// Dialing a grpc.ClientConn is hidden behind the dialer interface due to
// multiple reasons.
//
// In regular gRPC interactions, the target is communicated to the dialer via a
// string (URI or IP address). Behind the scenes, the dialer uses a the internal
// resolver and balancer to establish a connection.
//
// In the SCION model, we need a path in addition to the target address. We
// really do not want to encode it in a string. There are ways to get around
// this via attributes that a resolver can attach.
//
// Because we did not have a resolver mechanism in the RPC stack so far, clients
// resolved the path before calling the messenger. This mostly happens through
// the snet.Router interface. In addition to that, we have service resolution
// done by the messenger.AddressRewriter.
//
// Depending on the target of the RPC, dialing is slightly different. In
// general, we have three categories:
//  - Intra-AS communication: target=svc,concrete protocol=tcp
//  - regular Inter-AS communication: target=svc protocol=udp/scion
//  - bootstrapping Inter-AS communication: target=concrete, protocol=udp/scion
//
// For bootstrapping, the gRPC resolve mechanism cannot be used, as there is a
// circular dependency between having a path and doing bootstrap RPCs.
// Eventually, the dialer can, based on the type of the target address, decide
// whether to do resolution or not.
//
// Until we get there, clients need to have access to a Dialer that does the
// magic for them. The SCION Daemon will instantiate a Dialer that dials TCP to
// the appropriate service. The CS will instantiate a Dialer that dials
// UDP/SCION. CSes are expected to resolve the path before handing it to the
// dialer.
//
// Below is sample code how this might look like eventually.

// TCPDialer dials a gRPC connection over TCP. This dialer is meant to be used
// for AS internal communication, and is capable of resolving svc addresses.
type TCPDialer struct {
	SvcResolver func(addr.SVC) []resolver.Address
}

// Dial dials a gRPC connection over TCP. It resolves svc addresses.
func (t *TCPDialer) Dial(ctx context.Context, dst net.Addr) (*grpc.ClientConn, error) {
	var (
		target string
		opts   []grpc.DialOption
	)

	if v, ok := dst.(*snet.SVCAddr); ok {
		// resolve SVC→addresses
		targets := t.SvcResolver(v.SVC)
		if len(targets) == 0 {
			return nil, serrors.New("could not resolve")
		}

		// build a manual "svc" resolver
		r := manual.NewBuilderWithScheme("svc")
		r.InitialState(resolver.State{Addresses: targets})
		target = r.Scheme() + ":///" + v.SVC.BaseString()

		// use round_robin over our manual resolver
		opts = append(opts,
			grpc.WithResolvers(r),
			grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`),
		)
	} else {
		// prefix with passthrough:// to get the same behaviour
		// that the deprecated DialContext used.
		target = "passthrough:///" + dst.String()
	}

	// common options
	opts = append(opts,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		UnaryClientInterceptor(),
		StreamClientInterceptor(),
	)

	// NewClient replaces the deprecated DialContext / Dial
	return grpc.NewClient(target, opts...)
}

// AddressRewriter redirects to QUIC endpoints.
type AddressRewriter interface {
	RedirectToQUIC(ctx context.Context, address net.Addr) (net.Addr, error)
}

// ConnDialer dials a net.Conn.
type ConnDialer interface {
	Dial(context.Context, net.Addr) (net.Conn, error)
}

// QUICDialer dials a gRPC connection over QUIC/SCION. This dialer is meant to
// be used for inter AS communication, and is capable of resolving svc addresses.
type QUICDialer struct {
	Rewriter AddressRewriter
	Dialer   ConnDialer
}

// Dial dials a gRPC connection over QUIC/SCION.
func (d *QUICDialer) Dial(ctx context.Context, addr net.Addr) (*grpc.ClientConn, error) {
	// XXX(roosd): Eventually, this method should take advantage of the
	// resolver+balancer mechanism of gRPC. For now, keep the legacy behavior of
	// dialing a connection based on the QUIC redirects.

	addr, err := d.Rewriter.RedirectToQUIC(ctx, addr)
	if err != nil {
		return nil, serrors.Wrap("resolving SVC address", err)
	}
	if _, ok := addr.(*snet.UDPAddr); !ok {
		return nil, serrors.New("wrong address type after svc resolution",
			"type", common.TypeOf(addr))
	}
	dialer := func(context.Context, string) (net.Conn, error) {
		return d.Dialer.Dial(ctx, addr)
	}
	return grpc.NewClient(
		addr.String(),
		grpc.WithTransportCredentials(PassThroughCredentials{}),
		grpc.WithContextDialer(dialer),
		UnaryClientInterceptor(),
		StreamClientInterceptor(),
	)
}

var RetryOption grpc.CallOption = grpc_retry.WithPerRetryTimeout(3 * time.Second)

// RetryProfile is the common retry profile for RPCs.
var RetryProfile = []grpc.CallOption{
	RetryOption,
}
