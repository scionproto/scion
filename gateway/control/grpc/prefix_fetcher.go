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

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/serrors"
	gpb "github.com/scionproto/scion/pkg/proto/gateway"
	"github.com/scionproto/scion/pkg/snet"
)

// PrefixFetcher fetches prefixes from a gateway in a specific remote.
type PrefixFetcher struct {
	Remote addr.IA
	Pather control.PathMonitorRegistration
	Dialer grpc.Dialer
}

func (f PrefixFetcher) Prefixes(ctx context.Context, gateway *net.UDPAddr) ([]*net.IPNet, error) {
	paths := f.Pather.Get().Paths
	if len(paths) == 0 {
		return nil, serrors.New("no path available")
	}
	conn, err := f.Dialer.Dial(ctx, &snet.UDPAddr{
		IA:      f.Remote,
		Path:    paths[0].Dataplane(),
		NextHop: paths[0].UnderlayNextHop(),
		Host:    gateway,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := gpb.NewIPPrefixesServiceClient(conn)
	rep, err := client.Prefixes(ctx, &gpb.PrefixesRequest{}, grpc.RetryProfile...)
	if err != nil {
		return nil, serrors.Wrap("receiving IP prefixes", err)
	}
	prefixes := make([]*net.IPNet, 0, len(rep.Prefixes))
	for _, pb := range rep.Prefixes {
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
