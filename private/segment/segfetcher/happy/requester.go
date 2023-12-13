package happy

import (
	"context"
	"net"

	"github.com/scionproto/scion/pkg/connect/happy"
	"github.com/scionproto/scion/private/segment/segfetcher"
)

// Requester fetches segments from a remote using gRPC.
type Requester struct {
	Connect segfetcher.RPC
	Grpc    segfetcher.RPC
}

func (f *Requester) Segments(ctx context.Context, req segfetcher.Request,
	server net.Addr) (segfetcher.SegmentsReply, error) {

	return happy.Happy(
		ctx,
		happy.Call2[segfetcher.Request, net.Addr, segfetcher.SegmentsReply]{
			Call:   f.Connect.Segments,
			Input1: req,
			Input2: server,
			Typ:    "connect",
		},
		happy.Call2[segfetcher.Request, net.Addr, segfetcher.SegmentsReply]{
			Call:   f.Grpc.Segments,
			Input1: req,
			Input2: server,
			Typ:    "grpc",
		},
	)
}
