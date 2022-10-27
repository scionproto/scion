// Copyright 2017 ETH Zurich
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

// Package reliable implements the SCION ReliableSocket protocol
//
// Servers should first call Listen on a UNIX socket address, and then call
// Accept on the received Listener.
//
// Clients should either call:
//
//	Dial, if they do not want to register a receiving address with the remote end
//	  (e.g., when connecting to SCIOND);
//	Register, to register the address argument with the remote end
//	  (e.g., when connecting to a dispatcher).
//
// ReliableSocket common header message format:
//
//	8-bytes: COOKIE (0xde00ad01be02ef03)
//	1-byte: ADDR TYPE (NONE=0, IPv4=1, IPv6=2, SVC=3)
//	4-byte: data length
//	var-byte: Destination address (0 bytes for SCIOND API)
//	  +2-byte: If destination address not NONE, destination port
//	var-byte: Payload
//
// ReliableSocket registration message format:
//
//	13-bytes: [Common header with address type NONE]
//	 1-byte: Command (bit mask with 0x04=Bind address, 0x02=SCMP enable, 0x01 always set)
//	 1-byte: L4 Proto (IANA number)
//	 8-bytes: ISD-AS
//	 2-bytes: L4 port
//	 1-byte: Address type
//	 var-byte: Address
//	+2-bytes: L4 bind port  \
//	+1-byte: Address type    ) (optional bind address)
//	+var-byte: Bind Address /
//	+2-bytes: SVC (optional SVC type)
//
// To communicate with SCIOND, clients must first connect to SCIOND's UNIX socket. Messages
// for SCIOND must set the ADDR TYPE field in the common header to NONE. The payload contains
// the query for SCIOND (e.g., a request for paths to a SCION destination). The reply header
// contains the same fields, and the reply payload contains the query answer.
//
// To receive messages from remote SCION hosts, hosts can register their address and
// port with the SCION dispatcher. The common header of a registration message uses an address
// of type NONE. The payload contains the address type of the registered address, the address
// itself and the layer 4 port.
//
// To send messages to remote SCION hosts, hosts fill in the common header
// with the address type, the address and the layer 4 port of the remote host.
//
// Reads and writes to the connection are thread safe.
package reliable

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/sock/reliable/internal/metrics"
)

var (
	expectedCookie = uint64(0xde00ad01be02ef03)
)

const (
	// DefaultDispPath contains the system default for a dispatcher socket.
	DefaultDispPath = "/run/shm/dispatcher/default.sock"
	// DefaultDispSocketFileMode allows read/write to the user and group only.
	DefaultDispSocketFileMode = 0770
)

// Dispatcher controls how SCION applications open sockets in the SCION world.
type Dispatcher interface {
	// Register connects to a SCION Dispatcher's UNIX socket. Future messages for the address in AS
	// ia which arrive at the dispatcher can be read by calling Read on the returned connection.
	Register(ctx context.Context, ia addr.IA, address *net.UDPAddr,
		svc addr.HostSVC) (net.PacketConn, uint16, error)
}

// NewDispatcher creates a new dispatcher API endpoint on top of a UNIX
// STREAM reliable socket. If name is empty, the default dispatcher path is
// chosen.
func NewDispatcher(name string) Dispatcher {
	if name == "" {
		name = DefaultDispPath
	}
	return &dispatcherService{Address: name}
}

type dispatcherService struct {
	Address string
}

func (d *dispatcherService) Register(ctx context.Context, ia addr.IA, public *net.UDPAddr,
	svc addr.HostSVC) (net.PacketConn, uint16, error) {

	return registerMetricsWrapper(ctx, d.Address, ia, public, svc)
}

var _ net.Conn = (*Conn)(nil)
var _ net.PacketConn = (*Conn)(nil)

// Conn implements the ReliableSocket framing protocol over UNIX sockets.
type Conn struct {
	*net.UnixConn

	readMutex      sync.Mutex
	readBuffer     []byte
	readPacketizer *ReadPacketizer

	writeMutex    sync.Mutex
	writeBuffer   []byte
	writeStreamer *WriteStreamer
}

func newConn(c net.Conn) *Conn {
	conn := c.(*net.UnixConn)
	return &Conn{
		UnixConn:       c.(*net.UnixConn),
		writeBuffer:    make([]byte, common.SupportedMTU),
		writeStreamer:  NewWriteStreamer(conn),
		readBuffer:     make([]byte, common.SupportedMTU),
		readPacketizer: NewReadPacketizer(conn),
	}
}

// Dial connects to the UNIX socket specified by address.
//
// The provided context must be non-nil. If the context expires before the connection is complete,
// an error is returned. Once successfully connected, any expiration of the context will not affect
// the connection.
func Dial(ctx context.Context, address string) (*Conn, error) {
	dialer := net.Dialer{}
	c, err := dialer.DialContext(ctx, "unix", address)
	metrics.M.Dials(metrics.DialLabels{Result: labelResult(err)}).Inc()
	if err != nil {
		return nil, err
	}
	return newConn(c), nil
}

func registerMetricsWrapper(ctx context.Context, dispatcher string, ia addr.IA,
	public *net.UDPAddr, svc addr.HostSVC) (*Conn, uint16, error) {

	conn, port, err := register(ctx, dispatcher, ia, public, svc)
	labels := metrics.RegisterLabels{Result: labelResult(err), SVC: svc.BaseString()}
	metrics.M.Registers(labels).Inc()
	return conn, port, err
}

func register(ctx context.Context, dispatcher string, ia addr.IA, public *net.UDPAddr,
	svc addr.HostSVC) (*Conn, uint16, error) {

	reg := &Registration{
		IA:            ia,
		PublicAddress: public,
		SVCAddress:    svc,
	}

	conn, err := Dial(ctx, dispatcher)
	if err != nil {
		return nil, 0, err
	}

	type RegistrationReturn struct {
		port uint16
		err  error
	}
	resultChannel := make(chan RegistrationReturn)
	go func() {
		defer log.HandlePanic()

		// If a timeout was specified, make reads and writes return if deadline exceeded.
		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		}

		port, err := registrationExchange(conn, reg)
		resultChannel <- RegistrationReturn{port: port, err: err}
	}()

	select {
	case registrationReturn := <-resultChannel:
		if registrationReturn.err != nil {
			conn.Close()
			return nil, 0, registrationReturn.err
		}
		if public.Port < 0 || public.Port > math.MaxUint16 {
			return nil, 0, serrors.New(fmt.Sprintf("invalid port, range [0 - %v]", math.MaxUint16),
				"requested", public.Port)
		}
		if public.Port != 0 && public.Port != int(registrationReturn.port) {
			conn.Close()
			return nil, 0, serrors.New("port mismatch", "requested", public.Port,
				"received", registrationReturn.port)
		}
		// Disable deadline to not affect future I/O
		conn.SetDeadline(time.Time{})
		return conn, registrationReturn.port, nil
	case <-ctx.Done():
		// Unblock registration worker I/O
		conn.Close()
		// Wait for registration worker to finish before exiting. Worker should exit quickly
		// because all pending I/O immediately times out.
		<-resultChannel
		// The returned values aren't needed, we already decided to error out when the connection
		// was closed. Note that the registration might succeed in the short window of time between
		// the context being marked as done (canceled) and the I/O getting informed of the new
		// deadline.
		return nil, 0, serrors.WrapStr("timed out during dispatcher registration", ctx.Err())
	}
}

func registrationExchange(conn *Conn, reg *Registration) (uint16, error) {
	b := make([]byte, 1500)
	n, err := reg.SerializeTo(b)
	if err != nil {
		return 0, err
	}
	_, err = conn.WriteTo(b[:n], nil)
	if err != nil {
		return 0, err
	}

	n, _, err = conn.ReadFrom(b)
	if err != nil {
		conn.Close()
		return 0, err
	}

	var c Confirmation
	err = c.DecodeFromBytes(b[:n])
	if err != nil {
		conn.Close()
		return 0, err
	}
	return c.Port, nil

}

// ReadFrom works similarly to Read. In addition to Read, it also returns the last hop
// (usually, the border router) which sent the message.
func (conn *Conn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, addr, err := conn.readFrom(buf)
	metrics.M.Reads(metrics.IOLabels{Result: labelResult(err)}).Observe(float64(n))
	return n, addr, err
}

func (conn *Conn) readFrom(buf []byte) (int, net.Addr, error) {
	conn.readMutex.Lock()
	defer conn.readMutex.Unlock()

	n, err := conn.readPacketizer.Read(conn.readBuffer)
	if err != nil {
		return 0, nil, err
	}
	var p UnderlayPacket
	p.DecodeFromBytes(conn.readBuffer[:n])
	var underlayAddr *net.UDPAddr
	if p.Address != nil {
		underlayAddr = &net.UDPAddr{
			IP:   append(p.Address.IP[:0:0], p.Address.IP...),
			Port: p.Address.Port,
		}
	}
	if len(buf) < len(p.Payload) {
		return 0, nil, serrors.New("buffer too small")
	}
	copy(buf, p.Payload)
	return len(p.Payload), underlayAddr, nil
}

// WriteTo blocks until it sends buf as a single framed message through conn.
// The ReliableSocket message header will contain the address and port information in dst.
// On error, the number of bytes returned is meaningless. On success, the number of bytes
// is always len(buf).
func (conn *Conn) WriteTo(buf []byte, dst net.Addr) (int, error) {
	n, err := conn.writeTo(buf, dst)
	metrics.M.Writes(metrics.IOLabels{Result: labelResult(err)}).Observe(float64(n))
	return n, err
}

func (conn *Conn) writeTo(buf []byte, dst net.Addr) (int, error) {
	conn.writeMutex.Lock()
	defer conn.writeMutex.Unlock()

	var udpAddr *net.UDPAddr
	if dst != nil {
		var ok bool
		udpAddr, ok = dst.(*net.UDPAddr)
		if !ok {
			return 0, serrors.New("unsupported address type, must be UDP",
				"address", fmt.Sprintf("%#v", dst))
		}
	}
	p := &UnderlayPacket{Address: udpAddr, Payload: buf}
	n, err := p.SerializeTo(conn.writeBuffer)
	if err != nil {
		return 0, err
	}
	err = conn.writeStreamer.Write(conn.writeBuffer[:n])
	if err != nil {
		return 0, err
	}
	return len(buf), nil
}

// Read blocks until it reads the next framed message payload from conn and stores it in buf.
// The first return value contains the number of payload bytes read.
// buf must be large enough to fit the entire message. No addressing data is returned,
// only the payload. On error, the number of bytes returned is meaningless.
func (conn *Conn) Read(buf []byte) (int, error) {
	n, _, err := conn.ReadFrom(buf)
	return n, err
}

// Listener listens on Unix sockets and returns Conn sockets on Accept().
type Listener struct {
	*net.UnixListener
}

// Listen listens on UNIX socket laddr.
func Listen(laddr string) (*Listener, error) {
	l, err := net.Listen("unix", laddr)
	if err != nil {
		return nil, serrors.WrapStr("Unable to listen on address", err, "addr", laddr)
	}
	return &Listener{l.(*net.UnixListener)}, nil
}

// Accept returns sockets which implement the SCION ReliableSocket protocol for reading
// and writing.
func (listener *Listener) Accept() (net.Conn, error) {
	c, err := listener.UnixListener.Accept()
	if err != nil {
		return nil, err
	}
	return newConn(c), nil
}

func (listener *Listener) String() string {
	return fmt.Sprintf("&{addr: %v}", listener.UnixListener.Addr())
}

func labelResult(err error) string {
	switch {
	case err == nil:
		return prom.Success
	case serrors.IsTimeout(err):
		return prom.ErrTimeout
	default:
		return prom.ErrNotClassified
	}
}
