package connect

import (
	"context"
	"crypto/x509"
	"net"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/grpc"
)

type Fetcher struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// Dialer dials a new gRPC connection.
	Dialer func(net.Addr, ...squic.EarlyDialerOption) squic.EarlyDialer
}

// Chains fetches certificate chains over the network
func (f Fetcher) Chains(ctx context.Context, query trust.ChainQuery,
	server net.Addr) ([][]*x509.Certificate, error) {

	dialer := f.Dialer(server)
	client := control_planeconnect.NewTrustMaterialServiceClient(
		libconnect.HTTPClient{
			RoundTripper: &http3.RoundTripper{
				Dial: dialer.DialEarly,
			},
		},
		libconnect.BaseUrl(server),
	)
	rep, err := client.Chains(ctx, connect.NewRequest(grpc.ChainQueryToReq(query)))
	if err != nil {
		return nil, serrors.WrapStr("fetching chains over connect", err)
	}
	chains, _, err := grpc.RepToChains(rep.Msg.Chains)
	if err != nil {
		return nil, serrors.WrapStr("parsing chains", err)
	}
	if err := grpc.CheckChainsMatchQuery(query, chains); err != nil {
		return nil, serrors.WrapStr("chains do not match query", err)
	}
	return chains, nil
}

func (f Fetcher) TRC(ctx context.Context, id cppki.TRCID,
	server net.Addr) (cppki.SignedTRC, error) {

	dialer := f.Dialer(server)
	client := control_planeconnect.NewTrustMaterialServiceClient(
		libconnect.HTTPClient{
			RoundTripper: &http3.RoundTripper{
				Dial: dialer.DialEarly,
			},
		},
		libconnect.BaseUrl(server),
	)
	rep, err := client.TRC(ctx, connect.NewRequest(grpc.IDToReq(id)))
	if err != nil {
		return cppki.SignedTRC{}, serrors.WrapStr("fetching chains over connect", err)
	}
	trc, err := cppki.DecodeSignedTRC(rep.Msg.Trc)
	if err != nil {
		return cppki.SignedTRC{}, serrors.WrapStr("parse TRC reply", err)
	}
	if trc.TRC.ID != id {
		return cppki.SignedTRC{}, serrors.New("received wrong TRC", "expected", id,
			"actual", trc.TRC.ID)
	}
	return trc, nil
}
