package connect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/control/segreq/grpc"
	"github.com/scionproto/scion/pkg/proto/control_plane"
)

type LookupServer struct {
	grpc.LookupServer
}

func (s LookupServer) Segments(ctx context.Context, req *connect.Request[control_plane.SegmentsRequest]) (*connect.Response[control_plane.SegmentsResponse], error) {
	rep, err := s.LookupServer.Segments(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}
