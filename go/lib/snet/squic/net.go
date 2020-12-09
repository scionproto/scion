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
	"fmt"
	mrand "math/rand"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	// CtxTimedOutError is a custom QUIC error code that is used when canceling
	// writes due to context expiration.
	CtxTimedOutError quic.ErrorCode = iota + 1
	// OpenStreamError is the error code when failing to opening a stream.
	OpenStreamError
	// AcceptStreamError is the error code when failing to accept a stream.
	AcceptStreamError

	errNoError quic.ErrorCode = 0x100
)

// ConnListener wraps a quic.Listener as a net.Listener.
type ConnListener struct {
	quic.Listener

	ctx    context.Context
	cancel func()
}

// NewConnListener constructs a new listener with the appropriate buffers set.
func NewConnListener(l quic.Listener) *ConnListener {
	ctx, cancel := context.WithCancel(context.Background())
	c := &ConnListener{
		Listener: l,
		ctx:      ctx,
		cancel:   cancel,
	}
	return c
}

// Accept accepts the first stream on a session and wraps it as a net.Conn.
//
// XXX(roosd): Accept blocks until the first bytes on the stream are received.
// This will limit QPS heavily, but we should not yet be in a range where this
// matters too much.
func (l *ConnListener) Accept() (net.Conn, error) {
	session, err := l.Listener.Accept(l.ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(l.ctx, 5*time.Second)
	defer cancel()
	return acceptStream(ctx, session)
}

// AcceptCtx accepts the first stream on a session and wraps it as a net.Conn. Accepts a context in
// case the caller doesn't want this to block indefinitely.
func (l *ConnListener) AcceptCtx(ctx context.Context) (net.Conn, error) {
	session, err := l.Listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return acceptStream(ctx, session)
}

// Close closes the listener.
func (l *ConnListener) Close() error {
	l.cancel()
	return l.Listener.Close()
}

func acceptStream(ctx context.Context, session quic.Session) (net.Conn, error) {
	stream, err := session.AcceptStream(ctx)
	if err != nil {
		log.Debug("Accepting stream failed", "err", err)
	}
	return &acceptingConn{
		stream:  stream,
		Session: session,
		err:     err,
	}, nil
}

// ConnDialer dials a net.Conn over a QUIC stream.
type ConnDialer struct {
	// Conn is the connection to initiate QUIC Sessions on. It can be shared
	// between clients and servers, because QUIC connection IDs are used to
	// demux the packets.
	Conn net.PacketConn
	// TLSConfig is the client's TLS configuration for starting QUIC connections.
	TLSConfig *tls.Config
	// QUICConfig is the client's QUIC configuration.
	QUICConfig *quic.Config
}

// Dial dials a QUIC stream and returns it as a net.Conn.
//
// Note: This method dials with exponential backoff in case the dialing attempt
// fails due to a SERVER_BUSY error. Timers, number of attempts are EXPERIMENTAL
// and subject to change.
func (d ConnDialer) Dial(ctx context.Context, dst net.Addr) (net.Conn, error) {
	addressStr := computeAddressStr(dst)

	var session quic.Session
	for sleep := 2 * time.Millisecond; ctx.Err() == nil; sleep = sleep * 2 {
		var err error
		session, err = quic.DialContext(ctx, d.Conn, dst, addressStr, d.TLSConfig, d.QUICConfig)
		if err == nil {
			break
		}
		// Unfortunately there is no better way to check the error.
		// https://github.com/lucas-clemente/quic-go/issues/2441
		if err.Error() != "SERVER_BUSY" {
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
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		session.CloseWithError(OpenStreamError, "")
		return nil, serrors.WrapStr("opening stream", err)
	}
	return &acceptingConn{
		stream:  stream,
		Session: session,
	}, nil

}

// computeAddressStr returns a parseable version of the SCION address for use
// with QUIC SNI.
func computeAddressStr(address net.Addr) string {
	if v, ok := address.(*snet.UDPAddr); ok {
		return fmt.Sprintf("[%s]:%d", v.Host.IP, v.Host.Port)
	}
	return address.String()
}

type acceptingConn struct {
	stream quic.Stream
	quic.Session
	err error
}

func (c *acceptingConn) Read(b []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	return c.stream.Read(b)
}

func (c *acceptingConn) Write(b []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	return c.stream.Write(b)
}

func (c *acceptingConn) SetDeadline(t time.Time) error {
	if c.err != nil {
		return c.err
	}
	return c.stream.SetDeadline(t)
}

func (c *acceptingConn) SetReadDeadline(t time.Time) error {
	if c.err != nil {
		return c.err
	}
	return c.stream.SetReadDeadline(t)
}

func (c *acceptingConn) SetWriteDeadline(t time.Time) error {
	if c.err != nil {
		return c.err
	}
	return c.stream.SetWriteDeadline(t)
}

func (c *acceptingConn) Close() error {
	var errs []error
	if c.stream != nil {
		if err := c.stream.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := c.Session.CloseWithError(errNoError, ""); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 0 {
		return fmt.Errorf("closing connection: %v", errs)
	}
	return nil
}
