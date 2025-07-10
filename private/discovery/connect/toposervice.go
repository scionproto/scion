// Copyright 2025 SCION Association, Anapaya Systems
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

	dpb "github.com/scionproto/scion/pkg/proto/discovery"
	"github.com/scionproto/scion/pkg/proto/discovery/v1/discoveryconnect"
	"github.com/scionproto/scion/private/discovery"
)

var _ discoveryconnect.DiscoveryServiceHandler = Topology{}

type Topology struct {
	discovery.Topology
}

func (t Topology) Gateways(
	ctx context.Context,
	req *connect.Request[dpb.GatewaysRequest],
) (*connect.Response[dpb.GatewaysResponse], error) {
	rep, err := t.Topology.Gateways(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}

func (t Topology) HiddenSegmentServices(
	ctx context.Context,
	req *connect.Request[dpb.HiddenSegmentServicesRequest],
) (*connect.Response[dpb.HiddenSegmentServicesResponse], error) {
	rep, err := t.Topology.HiddenSegmentServices(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}
