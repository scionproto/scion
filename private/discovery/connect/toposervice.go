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
