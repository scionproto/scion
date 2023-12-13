package connect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/private/ca/renewal/grpc"
)

var _ control_planeconnect.ChainRenewalServiceHandler = RenewalServer{}

type RenewalServer struct {
	*grpc.RenewalServer
}

func (m RenewalServer) ChainRenewal(ctx context.Context, req *connect.Request[control_plane.ChainRenewalRequest]) (*connect.Response[control_plane.ChainRenewalResponse], error) {
	rep, err := m.RenewalServer.ChainRenewal(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}
