package connect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/control/trust/grpc"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
)

var _ control_planeconnect.TrustMaterialServiceHandler = MaterialServer{}

type MaterialServer struct {
	*grpc.MaterialServer
}

func (m MaterialServer) Chains(ctx context.Context, req *connect.Request[control_plane.ChainsRequest]) (*connect.Response[control_plane.ChainsResponse], error) {
	rep, err := m.MaterialServer.Chains(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}

func (m MaterialServer) TRC(ctx context.Context, req *connect.Request[control_plane.TRCRequest]) (*connect.Response[control_plane.TRCResponse], error) {
	rep, err := m.MaterialServer.TRC(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}
