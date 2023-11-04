package connect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/control/grpc"
	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/private/serrors"
	dpb "github.com/scionproto/scion/pkg/proto/discovery"
	"github.com/scionproto/scion/pkg/proto/discovery/v1/discoveryconnect"
	"github.com/scionproto/scion/pkg/snet"
)

// Discoverer discovers the gateways for a specific remote AS.
type Discoverer struct {
	// Remote is the ISD-AS of the remote AS.
	Remote addr.IA
	// Dialer dials a new QUIC connection.
	Dialer libconnect.Dialer
	// Paths is a registration for the paths to the remote AS.
	Paths control.PathMonitorRegistration
}

func (d Discoverer) Gateways(ctx context.Context) ([]control.Gateway, error) {
	paths := d.Paths.Get().Paths
	if len(paths) == 0 {
		return nil, serrors.New("no path available")
	}
	ds := &snet.SVCAddr{
		IA:      d.Remote,
		Path:    paths[0].Dataplane(),
		NextHop: paths[0].UnderlayNextHop(),
		SVC:     addr.SvcDS,
	}

	dialer := d.Dialer(ds)
	client := discoveryconnect.NewDiscoveryServiceClient(
		libconnect.HTTPClient{
			RoundTripper: &http3.RoundTripper{
				Dial: dialer.DialEarly,
			},
		},
		libconnect.BaseUrl(ds),
	)

	rep, err := client.Gateways(ctx, connect.NewRequest(&dpb.GatewaysRequest{}))
	if err != nil {
		return nil, serrors.WrapStr("receiving gateways", err)
	}
	return grpc.TransformGateways(rep.Msg.Gateways)
}
