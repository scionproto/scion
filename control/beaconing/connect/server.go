package connect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/control/beaconing/grpc"
	"github.com/scionproto/scion/pkg/proto/control_plane"
)

type SegmentCreationServer struct {
	grpc.SegmentCreationServer
}

func (s SegmentCreationServer) Beacon(ctx context.Context, req *connect.Request[control_plane.BeaconRequest]) (*connect.Response[control_plane.BeaconResponse], error) {
	rep, err := s.SegmentCreationServer.Beacon(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}
