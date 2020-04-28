// Copyright 2019 ETH Zurich, Anapaya Systems
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

// Package rpc implements SCION Infra RPC calls over QUIC.
package rpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
	capnp "zombiezen.com/go/capnproto2"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

const (
	// CtxTimedOutError is a custom QUIC error code that is used when canceling
	// writes due to context expiration.
	CtxTimedOutError = iota + 1

	errorNoError quic.ErrorCode = 0x100
)

// Server is the configuration for a QUIC RPC server. Messages are SCION Infra
// Signed Control Payloads. For each accepted connection, the server parses the
// message from the client and passes it to the handler.
type Server struct {
	// Conn is the connection to listen on. It can be shared with Clients,
	// because QUIC connection IDs are used to demux the packets.
	Conn net.PacketConn
	// TLSConfig is the server's TLS configuration for starting QUIC connections.
	TLSConfig *tls.Config
	// QUICConfig is the server's QUIC configuration.
	QUICConfig *quic.Config
	// Handler is called for every RPC Request receivd by the server.
	Handler Handler

	mu sync.Mutex
	// listener is the conn to accept connections on.
	listener quic.Listener
}

func (s *Server) ListenAndServe() error {
	if err := s.initListener(); err != nil {
		return err
	}
	for {
		session, err := s.listener.Accept(context.Background())
		if err != nil {
			if strings.Contains(err.Error(), "server closed") {
				return err
			}
			log.Warn("[quic] server accept error", "err", err)
			continue
		}
		if err := s.handleQUICSession(session); err != nil {
			log.Warn("[quic] server handler exited with error", "err", err)
		}
	}
}

func (s *Server) initListener() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return serrors.New("cannot listen on same server twice")
	}
	listener, err := quic.Listen(s.Conn, s.TLSConfig, s.QUICConfig)
	if err != nil {
		return err
	}
	s.listener = listener
	return nil
}

// Close closes the Server's listener. All active QUIC connections are
// immediately torn down. It is safe to call close multiple times.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		// Close on non-listening server is a no-op
		return nil
	}
	return s.listener.Close()
}

func (s *Server) handleQUICSession(session quic.Session) error {
	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		return err
	}
	msg, err := proto.SafeDecode(capnp.NewDecoder(stream))
	if err != nil {
		return err
	}
	rw := &replyWriter{stream: stream}
	request := &Request{
		Message: msg,
		Address: session.RemoteAddr(),
	}
	go func() {
		defer log.HandlePanic()
		s.Handler.ServeRPC(rw, request)
	}()
	return nil
}

type Client struct {
	// Conn is the connection to initiate QUIC Sessions on. It can be shared
	// with Servers, because QUIC connection IDs are used to demux the packets.
	Conn net.PacketConn
	// TLSConfig is the client's TLS configuration for starting QUIC connections.
	TLSConfig *tls.Config
	// QUICConfig is the client's QUIC configuration.
	QUICConfig *quic.Config
}

// Request sends the request to the host described by address, and blocks until
// a reply is received (or the context times out). If a reply is received, it
// is returned.
func (c *Client) Request(ctx context.Context, request *Request, address net.Addr) (*Reply, error) {
	addressStr := computeAddressStr(address)

	session, err := quic.DialContext(ctx, c.Conn, address, addressStr,
		c.TLSConfig, c.QUICConfig)
	if err != nil {
		return nil, err
	}

	stream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}
	go func() {
		defer log.HandlePanic()
		<-ctx.Done()
		stream.CancelRead(CtxTimedOutError)
		stream.CancelWrite(CtxTimedOutError)
	}()

	err = capnp.NewEncoder(stream).Encode(request.Message)
	if err != nil {
		return nil, err
	}
	msg, err := proto.SafeDecode(capnp.NewDecoder(stream))
	if err != nil {
		// if we have a timeout make it visible.
		if strings.Contains(err.Error(),
			fmt.Sprintf("canceled with error code %d", CtxTimedOutError)) && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}

	if err := stream.Close(); err != nil {
		return nil, err
	}
	if err := session.CloseWithError(errorNoError, ""); err != nil {
		return nil, err
	}
	return &Reply{Message: msg}, nil
}

func (c *Client) sendRequest() error {
	return nil
}

// computeAddressStr returns a parseable version of the SCION address for use
// with QUIC SNI.
func computeAddressStr(address net.Addr) string {
	if v, ok := address.(*snet.UDPAddr); ok {
		return fmt.Sprintf("[%s]:%d", v.Host.IP, v.Host.Port)
	}
	return address.String()
}

// Handler is called by RPC servers whenever a new request arrives.
// Implementations should write replies to rw.
type Handler interface {
	ServeRPC(rw ReplyWriter, request *Request)
}

// ReplyWriter provides handlers a way to respond to requests. ReplyWriter
// keeps a connection alive for replying. Method WriteReply can block; to
// unblock the method (and to close the connection ahead of time), call
// Close.  ReplyWriter implementations must also close the connection whenever
// they return from WriteReply.
type ReplyWriter interface {
	// WriteReply blocks until the Reply is sent back to the peer. The
	// underlying connection is always closed before WriteReply returns.
	WriteReply(*Reply) error
	// Close closes any connections kept open by this writer, and unblocks an
	// ongoing WriteReply. It is safe to call Close concurrently with
	// WriteReply. Close can be safely called multiple times.
	io.Closer
}

type replyWriter struct {
	stream quic.Stream
}

func (rw *replyWriter) WriteReply(reply *Reply) error {
	if err := capnp.NewEncoder(rw.stream).Encode(reply.Message); err != nil {
		return err
	}
	if err := rw.stream.Close(); err != nil {
		return err
	}
	return nil
}

func (rw *replyWriter) Close() error {
	return rw.stream.Close()
}
