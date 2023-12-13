package happy

import (
	"context"
	"crypto/x509"
	"net"

	"github.com/scionproto/scion/pkg/connect/happy"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
)

type Fetcher struct {
	Connect trust.Fetcher
	Grpc    trust.Fetcher
}

func (f Fetcher) Chains(ctx context.Context, query trust.ChainQuery,
	server net.Addr) ([][]*x509.Certificate, error) {

	return happy.Happy(
		ctx,
		happy.Call2[trust.ChainQuery, net.Addr, [][]*x509.Certificate]{
			Call:   f.Connect.Chains,
			Input1: query,
			Input2: server,
			Typ:    "connect",
		},
		happy.Call2[trust.ChainQuery, net.Addr, [][]*x509.Certificate]{
			Call:   f.Grpc.Chains,
			Input1: query,
			Input2: server,
			Typ:    "grpc",
		},
	)
}

func (f Fetcher) TRC(ctx context.Context, id cppki.TRCID,
	server net.Addr) (cppki.SignedTRC, error) {

	return happy.Happy(
		ctx,
		happy.Call2[cppki.TRCID, net.Addr, cppki.SignedTRC]{
			Call:   f.Connect.TRC,
			Input1: id,
			Input2: server,
			Typ:    "connect",
		},
		happy.Call2[cppki.TRCID, net.Addr, cppki.SignedTRC]{
			Call:   f.Grpc.TRC,
			Input1: id,
			Input2: server,
			Typ:    "grpc",
		},
	)
}
