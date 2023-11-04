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

	"github.com/scionproto/scion/pkg/private/serrors"
)

type EarlyDialerFactory struct {
	Transport *quic.Transport
}

func (f *EarlyDialerFactory) NewDialer(a net.Addr) EarlyDialer {
	return EarlyDialer{
		Transport: f.Transport,
		Addr:      a,
	}
}

type EarlyDialer struct {
	Transport *quic.Transport
	Addr      net.Addr
}

func (d *EarlyDialer) DialEarly(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
	serverName := tlsCfg.ServerName
	if serverName == "" {
		serverName = computeServerName(d.Addr)
	}

	var session quic.EarlyConnection
	for sleep := 2 * time.Millisecond; ctx.Err() == nil; sleep = sleep * 2 {
		// Clone TLS config to avoid data races.
		tlsConfig := tlsCfg.Clone()
		tlsConfig.ServerName = serverName
		// Clone QUIC config to avoid data races, if it exists.
		var quicConfig *quic.Config
		if cfg != nil {
			quicConfig = cfg.Clone()
		}

		var err error
		session, err = d.Transport.DialEarly(ctx, d.Addr, tlsConfig, quicConfig)
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
