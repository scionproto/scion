package connect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/control/segreg/grpc"
	"github.com/scionproto/scion/pkg/proto/control_plane"
)

type RegistrationServer struct {
	grpc.RegistrationServer
}

func (s RegistrationServer) SegmentsRegistration(ctx context.Context, req *connect.Request[control_plane.SegmentsRegistrationRequest]) (*connect.Response[control_plane.SegmentsRegistrationResponse], error) {
	rep, err := s.RegistrationServer.SegmentsRegistration(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}
