package conect

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
)

type QUICDialer struct {
	Rewriter   grpc.AddressRewriter
	Transport  *quic.Transport
	TLSConfig  *tls.Config
	QUICConfig *quic.Config
}

func (d *QUICDialer) DialEarly(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
	addr, _, err := d.Rewriter.RedirectToQUIC(ctx, addr)
	if err != nil {
		return nil, serrors.WrapStr("resolving SVC address", err)
	}
	if _, ok := addr.(*snet.UDPAddr); !ok {
		return nil, serrors.New("wrong address type after svc resolution",
			"type", common.TypeOf(addr))
	}
	dialer := squic.EarlyDialer{
		Addr:       addr,
		Transport:  d.Transport,
		TLSConfig:  d.TLSConfig,
		QUICConfig: d.QUICConfig,
	}
	return dialer.DialEarly(ctx, "", nil, nil)
}
