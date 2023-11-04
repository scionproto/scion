// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package squic

import (
	"context"
	"crypto/tls"
	"errors"
	mrand "math/rand"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

type AddressRewriter interface {
	RedirectToQUIC(ctx context.Context, address net.Addr) (net.Addr, bool, error)
}

type EarlyDialerFactory struct {
	Transport  *quic.Transport
	TLSConfig  *tls.Config
	QUICConfig *quic.Config
	Rewriter   AddressRewriter
}

func (f *EarlyDialerFactory) NewDialer(a net.Addr) EarlyDialer {
	return EarlyDialer{
		Addr:       a,
		Transport:  f.Transport,
		TLSConfig:  f.TLSConfig,
		QUICConfig: f.QUICConfig,
		Rewriter:   f.Rewriter,
	}
}

type EarlyDialer struct {
	Addr       net.Addr
	Transport  *quic.Transport
	TLSConfig  *tls.Config
	QUICConfig *quic.Config
	Rewriter   AddressRewriter
}

func (d *EarlyDialer) DialEarly(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
	addr, _, err := d.Rewriter.RedirectToQUIC(ctx, d.Addr)
	if err != nil {
		return nil, serrors.WrapStr("resolving SVC address", err)
	}
	if _, ok := addr.(*snet.UDPAddr); !ok {
		return nil, serrors.New("wrong address type after svc resolution",
			"type", common.TypeOf(addr))
	}

	serverName := d.TLSConfig.ServerName
	if serverName == "" {
		serverName = computeServerName(addr)
	}

	var session quic.EarlyConnection
	for sleep := 2 * time.Millisecond; ctx.Err() == nil; sleep = sleep * 2 {
		// Clone TLS config to avoid data races.
		tlsConfig := d.TLSConfig.Clone()
		tlsConfig.ServerName = serverName
		// Clone QUIC config to avoid data races, if it exists.
		var quicConfig *quic.Config
		if d.QUICConfig != nil {
			quicConfig = d.QUICConfig.Clone()
		}

		var err error
		session, err = d.Transport.DialEarly(ctx, addr, tlsConfig, quicConfig)
		if err == nil {
			break
		}
		var transportErr *quic.TransportError
		if !errors.As(err, &transportErr) || transportErr.ErrorCode != quic.ConnectionRefused {
			return nil, serrors.WrapStr("dialing QUIC/SCION", err)
		}

		jitter := time.Duration(mrand.Int63n(int64(5 * time.Millisecond)))
		select {
		case <-time.After(sleep + jitter):
		case <-ctx.Done():
			return nil, serrors.WrapStr("timed out connecting to busy server", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, serrors.WrapStr("dialing QUIC/SCION, after loop", err)
	}
	return session, nil
}
