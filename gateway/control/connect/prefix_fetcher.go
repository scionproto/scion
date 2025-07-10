// Copyright 2023 Anapaya Systems
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

package connect

import (
	"context"
	"net"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go/http3"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/private/serrors"
	gpb "github.com/scionproto/scion/pkg/proto/gateway"
	"github.com/scionproto/scion/pkg/proto/gateway/v1/gatewayconnect"
	"github.com/scionproto/scion/pkg/snet"
)

// PrefixFetcher fetches prefixes from a gateway in a specific remote AS.
type PrefixFetcher struct {
	// Remote is the ISD-AS of the remote AS.
	Remote addr.IA
	// Dialer dials a new QUIC connection.
	Dialer libconnect.Dialer
	// Paths is a registration for the paths to the remote AS.
	Paths control.PathMonitorRegistration
}

func (f PrefixFetcher) Prefixes(ctx context.Context, gateway *net.UDPAddr) ([]*net.IPNet, error) {
	paths := f.Paths.Get().Paths
	if len(paths) == 0 {
		return nil, serrors.New("no path available")
	}
	remote := &snet.UDPAddr{
		IA:      f.Remote,
		Path:    paths[0].Dataplane(),
		NextHop: paths[0].UnderlayNextHop(),
		Host:    gateway,
	}

	dialer := f.Dialer(remote)
	client := gatewayconnect.NewIPPrefixesServiceClient(
		libconnect.HTTPClient{
			RoundTripper: &http3.Transport{
				Dial: dialer.DialEarly,
			},
		},
		libconnect.BaseUrl(remote),
	)
	rep, err := client.Prefixes(ctx, connect.NewRequest(&gpb.PrefixesRequest{}))
	if err != nil {
		return nil, serrors.Wrap("receiving IP prefixes", err)
	}
	prefixes := make([]*net.IPNet, 0, len(rep.Msg.Prefixes))
	for _, pb := range rep.Msg.Prefixes {
		mask := net.CIDRMask(int(pb.Mask), len(pb.Prefix)*8)
		if mask == nil {
			continue
		}
		prefixes = append(prefixes, &net.IPNet{
			IP:   pb.Prefix,
			Mask: mask,
		})
	}
	return prefixes, nil
}
