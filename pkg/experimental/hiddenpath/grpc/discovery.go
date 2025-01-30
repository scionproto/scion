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

	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/serrors"
	dspb "github.com/scionproto/scion/pkg/proto/discovery"
)

// Discoverer can be used to discover remote hidden path instances.
type Discoverer struct {
	// Dialer dials a new gRPC connection.
	Dialer grpc.Dialer
}

// Discover discovers hidden path services at the discovery service that is
// given by the address.
func (d *Discoverer) Discover(ctx context.Context, dsAddr net.Addr) (hiddenpath.Servers, error) {
	conn, err := d.Dialer.Dial(ctx, dsAddr)
	if err != nil {
		return hiddenpath.Servers{}, serrors.Wrap("dialing", err)
	}
	defer conn.Close()
	client := dspb.NewDiscoveryServiceClient(conn)
	r, err := client.HiddenSegmentServices(ctx, &dspb.HiddenSegmentServicesRequest{},
		grpc.RetryProfile...)
	if err != nil {
		return hiddenpath.Servers{}, err
	}
	reply := hiddenpath.Servers{
		Lookup:       make([]*net.UDPAddr, 0, len(r.Lookup)),
		Registration: make([]*net.UDPAddr, 0, len(r.Registration)),
	}
	parseUDPAddr := func(addr string) (*net.UDPAddr, error) {
		a, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		if ip4 := a.IP.To4(); ip4 != nil {
			a.IP = ip4
		}
		return a, nil
	}
	for _, l := range r.Lookup {
		a, err := parseUDPAddr(l.Address)
		if err != nil {
			return hiddenpath.Servers{}, serrors.Wrap("parsing address", err, "raw", l.Address)
		}
		reply.Lookup = append(reply.Lookup, a)
	}
	for _, l := range r.Registration {
		a, err := parseUDPAddr(l.Address)
		if err != nil {
			return hiddenpath.Servers{}, serrors.Wrap("parsing address", err, "raw", l.Address)
		}
		reply.Registration = append(reply.Registration, a)
	}
	return reply, nil
}
