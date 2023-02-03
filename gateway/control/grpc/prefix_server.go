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
	"net/netip"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics"
	gpb "github.com/scionproto/scion/pkg/proto/gateway"
	"github.com/scionproto/scion/pkg/snet"
)

// Advertiser returns a list of IP prefixes to advertise.
type Advertiser interface {
	AdvertiseList(from, to addr.IA) ([]netip.Prefix, error)
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
	prefixes, err := s.Advertiser.AdvertiseList(s.LocalIA, udp.IA)
	if err != nil {
		return nil, err
	}
	metrics.GaugeSet(metrics.GaugeWith(s.PrefixesAdvertised,
		"remote_isd_as", udp.IA.String()), float64(len(prefixes)))

	pb := make([]*gpb.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		pb = append(pb, &gpb.Prefix{
			Prefix: canonicalIP(prefix.Addr()),
			Mask:   uint32(prefix.Bits()),
		})
	}
	return &gpb.PrefixesResponse{
		Prefixes: pb,
	}, nil
}

func canonicalIP(ip netip.Addr) []byte {
	if ip.Is4() {
		a4 := ip.As4()
		return append([]byte(nil), a4[:]...)
	}
	a16 := ip.As16()
	return append([]byte(nil), a16[:]...)
}
