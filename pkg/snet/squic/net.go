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
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

const (
	// CtxTimedOutError is a custom QUIC error code that is used when canceling
	// writes due to context expiration.
	CtxTimedOutError quic.ApplicationErrorCode = iota + 1
	// OpenStreamError is the error code when failing to opening a stream.
	OpenStreamError
	// AcceptStreamError is the error code when failing to accept a stream.
	AcceptStreamError

	errNoError quic.ApplicationErrorCode = 0x100
)

// streamAcceptTimeout is the default timeout for accepting connections.
const streamAcceptTimeout = 5 * time.Second

// ConnListener wraps a quic.Listener as a net.Listener.
type ConnListener struct {
	*quic.Listener

	ctx    context.Context
	cancel func()
}

// NewConnListener constructs a new listener with the appropriate buffers set.
func NewConnListener(l *quic.Listener) *ConnListener {
	ctx, cancel := context.WithCancel(context.Background())
	c := &ConnListener{
		Listener: l,
		ctx:      ctx,
		cancel:   cancel,
	}
	return c
}

// Accept accepts the first stream on a session and wraps it as a net.Conn.
func (l *ConnListener) Accept() (net.Conn, error) {
	session, err := l.Listener.Accept(l.ctx)
	if err != nil {
		return nil, err
	}
	return newAcceptingConn(l.ctx, session), nil
}

// AcceptCtx accepts the first stream on a session and wraps it as a net.Conn. Accepts a context in
// case the caller doesn't want this to block indefinitely.
func (l *ConnListener) AcceptCtx(ctx context.Context) (net.Conn, error) {
	session, err := l.Listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return newAcceptingConn(ctx, session), nil
}

// Close closes the listener.
func (l *ConnListener) Close() error {
	l.cancel()
	return l.Listener.Close()
}

// acceptingConn is a net.Conn wrapper for a QUIC stream that is yet to
// be accepted. The connection is accepted with the first call to Read or
// Write.
type acceptingConn struct {
	session quic.Connection

	// once ensures that the stream is accepted at most once.
	once sync.Once
	// acceptedStream is closed as soon as soon as we are done attempting
	// to accept the stream.
	acceptedStream chan struct{}

	// deadlineStreamMtx protects the deadline and stream from concurrent
	// access. It is used to avoid a race between setting the deadline
	// on accept and through the setter methods.
	deadlineStreamMtx sync.Mutex
	// stream contains the accepted stream.
	stream quic.Stream
	// err contains the potential error during accepting the stream.
	err error
	// readDeadline keeps track of the deadline that is set on the conn
	// before it has been accepted.
	readDeadline time.Time
	// writeDeadline keeps track of the deadline that is set on the conn before
	// it has been accepted.
	writeDeadline time.Time

	acceptCtx       context.Context
	acceptCtxCancel context.CancelFunc
	acceptDeadline  time.Time
	timer           *time.Timer
}

// newAcceptingConn constructs a new acceptingConn. The context restricts the
// time spent on accepting the stream.
func newAcceptingConn(ctx context.Context, session quic.Connection) net.Conn {
	var cancel context.CancelFunc

	// Use deadline from parent if it exists. Otherwise, use default.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(streamAcceptTimeout)
		ctx, cancel = context.WithDeadline(ctx, deadline)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	// The timer triggers when the deadline is hit.
	// This is only needed to implement the Set{Read,Write}Deadline behavior
	// correctly in case we have to wait for the accept.
	timer := time.NewTimer(time.Until(deadline))
	go func() {
		defer log.HandlePanic()
		select {
		case <-ctx.Done():
		case <-timer.C:
			cancel()
		}
	}()

	return &acceptingConn{
		acceptedStream:  make(chan struct{}),
		session:         session,
		acceptCtx:       ctx,
		acceptCtxCancel: cancel,
		acceptDeadline:  deadline,
		timer:           timer,
	}
}

func (c *acceptingConn) Read(b []byte) (n int, err error) {
	c.acceptStream()
	stream, err := c.waitForStream()
	if err != nil {
		return 0, err
	}
	return stream.Read(b)
}

func (c *acceptingConn) Write(b []byte) (n int, err error) {
	c.acceptStream()
	stream, err := c.waitForStream()
	if err != nil {
		return 0, err
	}
	return stream.Write(b)
}

// waitForStream blocks until a stream has been accepted, or failed to accept.
func (c *acceptingConn) waitForStream() (quic.Stream, error) {
	<-c.acceptedStream
	return c.stream, c.err
}

// acceptStream accepts a stream and sets the c.stream and c.err values.
// After a stream has been accepted, or it failed to accept, the
// acceptedStream channel is closed.
func (c *acceptingConn) acceptStream() {
	c.once.Do(c.acceptStreamOnce)
}

func (c *acceptingConn) acceptStreamOnce() {
	// Cancel the context to free the go routine waiting for the ticker.
	defer c.acceptCtxCancel()
	// Unblock routines that wait for the stream to be accepted.
	defer close(c.acceptedStream)

	// Accept the stream outside of the deadlineStreamMtx lock to
	// allow setting the deadlines concurrently with accepting.
	// This is especially important when the calling code wants
	// to reduce the timeout. If this code is in the guarded
	// block below, the timer cannot be adjusted with a call
	// to Set{Read,Write}Deadline.
	stream, err := c.session.AcceptStream(c.acceptCtx)

	// We need to protect against races with Set{Read,Write}Deadline.
	c.deadlineStreamMtx.Lock()
	defer c.deadlineStreamMtx.Unlock()

	c.stream, c.err = stream, err
	if c.err != nil {
		log.Debug("Accepting stream failed", "err", c.err)
		return
	}

	// Potentially set the deadlines to the values that were set before the
	// stream was accepted.
	c.err = serrors.Join(
		c.stream.SetReadDeadline(c.readDeadline),
		c.stream.SetWriteDeadline(c.writeDeadline),
	)
}

func (c *acceptingConn) SetDeadline(t time.Time) error {
	c.deadlineStreamMtx.Lock()
	defer c.deadlineStreamMtx.Unlock()

	// Check if we have already a stream that is accepted.
	stream, err := c.getStreamLocked()
	if err != nil {
		return err
	}
	if stream != nil {
		return stream.SetDeadline(t)
	}

	// The stream has not been accepted yet.
	c.readDeadline = t
	c.writeDeadline = t
	return c.setTimerLocked()
}

func (c *acceptingConn) SetReadDeadline(t time.Time) error {
	c.deadlineStreamMtx.Lock()
	defer c.deadlineStreamMtx.Unlock()

	// Check if we have already a stream that is accepted.
	stream, err := c.getStreamLocked()
	if err != nil {
		return err
	}
	if stream != nil {
		return c.stream.SetReadDeadline(t)
	}

	// The stream has not been accepted yet
	c.readDeadline = t
	return c.setTimerLocked()
}

func (c *acceptingConn) SetWriteDeadline(t time.Time) error {
	c.deadlineStreamMtx.Lock()
	defer c.deadlineStreamMtx.Unlock()

	// Check if we have already a stream that is accepted.
	stream, err := c.getStreamLocked()
	if err != nil {
		return err
	}
	if stream != nil {
		return c.stream.SetWriteDeadline(t)
	}

	// The stream has not been accepted yet
	c.writeDeadline = t
	return c.setTimerLocked()
}

// getStreamLocked returns the stream and error. It assumes that the
// deadlineStreamMtx lock is held.
func (c *acceptingConn) getStreamLocked() (quic.Stream, error) {
	return c.stream, c.err
}

// getTimerLocked resets the timer. It assumes that the deadlineStreamMtx lock
// is held.
func (c *acceptingConn) setTimerLocked() error {
	if !c.timer.Stop() {
		return serrors.New("accept timer already fired")
	}
	// We do not need to drain the ticker channel. If we reach this branch of
	// the code, it means that the ticker was active and has not fired yet.
	// This, coupled with the fact that we never reset a timer that has fired or
	// stopped guarantees that there is nothing on the channel when we reset
	// the timer.

	deadline := c.acceptDeadline
	if !c.readDeadline.IsZero() && c.readDeadline.Before(deadline) {
		deadline = c.readDeadline
	}
	if !c.writeDeadline.IsZero() && c.writeDeadline.Before(deadline) {
		deadline = c.writeDeadline
	}
	c.timer.Reset(time.Until(deadline))
	return nil
}

func (c *acceptingConn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

func (c *acceptingConn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

func (c *acceptingConn) ConnectionState() tls.ConnectionState {
	return c.session.ConnectionState().TLS
}

func (c *acceptingConn) Close() error {
	// Prevent the stream from being accepted.
	c.once.Do(func() {
		c.err = serrors.New("connection is closed")
		close(c.acceptedStream)
	})

	// Cancel potentially accepting routine and wait for it to finish.
	c.acceptCtxCancel()
	stream, _ := c.waitForStream()

	var errs []error
	if stream != nil {
		if err := stream.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := c.session.CloseWithError(errNoError, ""); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 0 {
		return fmt.Errorf("closing connection: %v", errs)
	}
	return nil
}

// ConnDialer dials a net.Conn over a QUIC stream.
type ConnDialer struct {
	// Conn is the transport to initiate QUIC Sessions on. It can be shared
	// between clients and servers, because QUIC connection IDs are used to
	// demux the packets.
	//
	// Note: When creating the transport, ensure that the SCMP errors are not
	// propagated. You can for example use
	// [github.com/scionproto/scion/pkg/snet.SCMPPropagationStopper]. Otherwise,
	// the QUIC transport will close the listening side on SCMP errors and enter
	// a broken state.
	Transport *quic.Transport
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
	if d.TLSConfig == nil {
		return nil, serrors.New("tls.Config not set")
	}
	serverName := d.TLSConfig.ServerName
	if serverName == "" {
		serverName = computeServerName(dst)
	}

	var session quic.Connection
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
		session, err = d.Transport.Dial(ctx, dst, tlsConfig, quicConfig)
		if err == nil {
			break
		}
		var transportErr *quic.TransportError
		if !errors.As(err, &transportErr) || transportErr.ErrorCode != quic.ConnectionRefused {
			return nil, serrors.Wrap("dialing QUIC/SCION", err)
		}

		jitter := time.Duration(rand.Int64N(int64(5 * time.Millisecond)))
		select {
		case <-time.After(sleep + jitter):
		case <-ctx.Done():
			return nil, serrors.Wrap("timed out connecting to busy server", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, serrors.Wrap("dialing QUIC/SCION, after loop", err)
	}
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		_ = session.CloseWithError(OpenStreamError, "")
		return nil, serrors.Wrap("opening stream", err)
	}
	return &acceptedConn{
		stream:  stream,
		session: session,
	}, nil

}

// computeServerName returns a parseable version of the SCION address for use
// with QUIC SNI.
func computeServerName(address net.Addr) string {
	// XXX(roosd): Special case snet.UDPAddr because its string encoding is not
	// processable by net.SplitHostPort.
	if v, ok := address.(*snet.UDPAddr); ok {
		return fmt.Sprintf("%s,%s", v.IA, v.Host.IP)
	}
	host := address.String()
	sni, _, err := net.SplitHostPort(host)
	if err != nil {
		// It's ok if net.SplitHostPort returns an error. it could be a
		// hostname/IP address without a port.
		sni = host
	}
	return sni
}

// acceptedConn is a net.Conn wrapper for a QUIC stream.
type acceptedConn struct {
	stream  quic.Stream
	session quic.Connection
}

func (c *acceptedConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *acceptedConn) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

func (c *acceptedConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *acceptedConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *acceptedConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (c *acceptedConn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

func (c *acceptedConn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

func (c *acceptedConn) ConnectionState() tls.ConnectionState {
	return c.session.ConnectionState().TLS
}

func (c *acceptedConn) Close() error {
	var errs []error
	if err := c.stream.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := c.session.CloseWithError(errNoError, ""); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 0 {
		return fmt.Errorf("closing connection: %v", errs)
	}
	return nil
}
