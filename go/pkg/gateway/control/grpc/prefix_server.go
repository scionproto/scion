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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/snet"
	gpb "github.com/scionproto/scion/go/pkg/proto/gateway"
)

// Advertiser returns a list of IP prefixes to advertise.
type Advertiser interface {
	AdvertiseList(from, to addr.IA) []*net.IPNet
}

// IPPrefixServer serves IP prefix requests.
type IPPrefixServer struct {
	// LocalIA is the IA of the local AS.
	LocalIA addr.IA
	// Advertiser is the advertiser used to get the list of prefixes to advertise.
	Advertiser Advertiser
	// PrefixesAdvertised reports the number of IP prefixes advertised. If nil, no  metrics are
	// reported.
	PrefixesAdvertised metrics.Gauge
}

func (s IPPrefixServer) Prefixes(ctx context.Context,
	req *gpb.PrefixesRequest) (*gpb.PrefixesResponse, error) {

	remote, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "peer required")
	}
	udp, ok := remote.Addr.(*snet.UDPAddr)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "SCION peer required")
	}
	prefixes := s.Advertiser.AdvertiseList(s.LocalIA, udp.IA)
	metrics.GaugeSet(metrics.GaugeWith(s.PrefixesAdvertised,
		"remote_isd_as", udp.IA.String()), float64(len(prefixes)))

	pb := make([]*gpb.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		ones, bits := prefix.Mask.Size()
		if bits == 0 {
			continue
		}
		pb = append(pb, &gpb.Prefix{
			Prefix: canonicalIP(prefix.IP),
			Mask:   uint32(ones),
		})
	}
	return &gpb.PrefixesResponse{
		Prefixes: pb,
	}, nil
}

func canonicalIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
