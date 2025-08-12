// Copyright 2025 SCION Association, Anapaya Systems
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

package connect

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/scionproto/scion/pkg/log"
)

// AttachPeer creates a middleware that attaches the remote address to the
// context with the grpc-go peer mechanism.
func AttachPeer(next http.Handler) http.Handler {
	authInfo := func(r *http.Request) credentials.AuthInfo {
		if r.TLS == nil {
			return nil
		}
		if r.TLS.PeerCertificates == nil {
			return nil
		}
		return credentials.TLSInfo{
			State: *r.TLS,
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := log.FromCtx(r.Context())
		if addr, ok := r.Context().Value(http3.RemoteAddrContextKey).(net.Addr); ok {
			logger.Debug("HTTP3 request", "remote", addr)
			ctx := peer.NewContext(r.Context(), &peer.Peer{Addr: addr, AuthInfo: authInfo(r)})
			r = r.WithContext(ctx)
		} else if addrPort, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			logger.Debug("HTTP request", "remote", addrPort)
			tcpAddr := net.TCPAddrFromAddrPort(addrPort)
			ctx := peer.NewContext(r.Context(), &peer.Peer{Addr: tcpAddr, AuthInfo: authInfo(r)})
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

type QUICConnServer interface {
	ServeQUICConn(conn *quic.Conn) error
}

type QUICConnServerFunc func(conn *quic.Conn) error

func (f QUICConnServerFunc) ServeQUICConn(conn *quic.Conn) error {
	return f(conn)
}

type ConnectionDispatcher struct {
	Listener *quic.Listener
	Connect  QUICConnServer
	Grpc     QUICConnServer
	Error    func(error)
}

// Run accepts connections and dispatches them to the appropriate server
// handler.
func (d ConnectionDispatcher) Run(ctx context.Context) error {
	for {
		conn, err := d.Listener.Accept(ctx)
		if err == quic.ErrServerClosed {
			return http.ErrServerClosed
		}
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		go func() {
			defer log.HandlePanic()
			if d.Connect != nil && conn.ConnectionState().TLS.NegotiatedProtocol == "h3" {
				if err := d.Connect.ServeQUICConn(conn); err != nil {
					d.Error(err)
				}
			} else if d.Grpc != nil {
				if err := d.Grpc.ServeQUICConn(conn); err != nil {
					d.Error(err)
				}
			}
		}()
	}
}
