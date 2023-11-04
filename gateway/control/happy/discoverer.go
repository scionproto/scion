package happy

import (
	"context"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/pkg/connect/happy"
)

type Discoverer struct {
	Connect control.Discoverer
	Grpc    control.Discoverer
}

func (d Discoverer) Gateways(ctx context.Context) ([]control.Gateway, error) {
	return happy.Happy(
		ctx,
		happy.Call0[[]control.Gateway]{
			Call: d.Connect.Gateways,
			Typ:  "discovery.v1.DiscoveryService.Gateways",
		},
		happy.Call0[[]control.Gateway]{
			Call: d.Grpc.Gateways,
			Typ:  "discovery.v1.DiscoveryService.Gateways",
		},
	)
}
