// Copyright 2026 ETH Zurich
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

	"connectrpc.com/connect"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/private/topology"
)

type UnderlayServer struct {
	Topology *topology.Loader
	Requests metrics.Counter
}

func (u UnderlayServer) ListUnderlays(ctx context.Context,
	req *connect.Request[endhost.ListUnderlaysRequest]) (
	*connect.Response[endhost.ListUnderlaysResponse], error) {

	// TODO: Parameter IsdAs is currently ignored since only a single IsdAS is supported
	// TODO: Currently only the UDP Underlay is returned, add support for snap later
	logger := log.FromCtx(ctx)
	logger.Debug("Received ListUnderlays request")

	res := &endhost.ListUnderlaysResponse{
		Udp: &endhost.UdpUnderlay{},
	}

	ia := u.Topology.IA()
	portStart, portEnd := u.Topology.PortRange()
	routers, _ := u.Topology.BorderRouters()
	for _, router := range routers {
		interfaces := make([]uint32, len(router.IfIDs))
		for i, ifID := range router.IfIDs {
			interfaces[i] = uint32(ifID)
		}
		res.Udp.Routers = append(res.Udp.Routers, &endhost.Router{
			IsdAs:      uint64(ia),
			Address:    router.InternalAddr.String(),
			Interfaces: interfaces,
			DispatchedRange: &endhost.Router_PortRange{
				DispatchedPortStart: uint32(portStart),
				DispatchedPortEnd:   uint32(portEnd),
			},
		})
	}
	logger.Debug("Replied with", "udp underlay routers", len(routers))
	if u.Requests != nil {
		u.Requests.Add(1)
	}
	return connect.NewResponse(res), nil
}
