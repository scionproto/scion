package happy

import (
	"context"
	"net"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/pkg/connect/happy"
)

type PrefixFetcher struct {
	Connect control.SimplePrefixFetcher
	Grpc    control.SimplePrefixFetcher
}

func (f PrefixFetcher) Prefixes(ctx context.Context, gateway *net.UDPAddr) ([]*net.IPNet, error) {
	return happy.Happy(
		ctx,
		happy.Call1[*net.UDPAddr, []*net.IPNet]{
			Call:   f.Connect.Prefixes,
			Input1: gateway,
			Typ:    "gateway.v1.IPPrefixesService.Prefixes",
		},
		happy.Call1[*net.UDPAddr, []*net.IPNet]{
			Call:   f.Grpc.Prefixes,
			Input1: gateway,
			Typ:    "gateway.v1.IPPrefixesService.Prefixes",
		},
	)
}
