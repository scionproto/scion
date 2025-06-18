package connect

import (
	"context"
	"net"
	"net/http"
	"net/netip"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"google.golang.org/grpc/peer"

	"github.com/scionproto/scion/pkg/log"
)

// AttachPeer creates a middleware that attaches the remote address to the
// context with the grpc-go peer mechanism.
func AttachPeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := log.FromCtx(r.Context())
		if addr, ok := r.Context().Value(http3.RemoteAddrContextKey).(net.Addr); ok {
			logger.Debug("HTTP3 request", "remote", addr)
			ctx := peer.NewContext(r.Context(), &peer.Peer{Addr: addr})
			r = r.WithContext(ctx)
		} else if addrPort, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			logger.Debug("HTTP request", "remote", addrPort)
			tcpAddr := net.TCPAddrFromAddrPort(addrPort)
			ctx := peer.NewContext(r.Context(), &peer.Peer{Addr: tcpAddr})
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})

}

type QUICConnServer interface {
	ServeQUICConn(conn quic.Connection) error
}

type QUICConnServerFunc func(conn quic.Connection) error

func (f QUICConnServerFunc) ServeQUICConn(conn quic.Connection) error {
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
			// If the context has been canceled, we do not report an error.
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer log.HandlePanic()
			if conn.ConnectionState().TLS.NegotiatedProtocol == "h3" {
				if err := d.Connect.ServeQUICConn(conn); err != nil {
					d.Error(err)
				}
			} else {
				if err := d.Grpc.ServeQUICConn(conn); err != nil {
					d.Error(err)
				}
			}
		}()
	}
}
