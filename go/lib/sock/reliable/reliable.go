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
//   Dial, if they do not want to register a receiving address with the remote end
//     (e.g., when connecting to SCIOND);
//   Register, to register the address argument with the remote end
//     (e.g., when connecting to a dispatcher).
//
// ReliableSocket common header message format:
//   8-bytes: COOKIE (0xde00ad01be02ef03)
//   1-byte: ADDR TYPE (NONE=0, IPv4=1, IPv6=2, SVC=3)
//   4-byte: data length
//   var-byte: Destination address (0 bytes for SCIOND API)
//     +2-byte: If destination address not NONE, destination port
//   var-byte: Payload
//
// ReliableSocket registration message format:
//  13-bytes: [Common header with address type NONE]
//   1-byte: Command (bit mask with 0x04=Bind address, 0x02=SCMP enable, 0x01 always set)
//   1-byte: L4 Proto (IANA number)
//   8-bytes: ISD-AS
//   2-bytes: L4 port
//   1-byte: Address type
//   var-byte: Address
//  +2-bytes: L4 bind port  \
//  +1-byte: Address type    ) (optional bind address)
//  +var-byte: Bind Address /
//  +2-bytes: SVC (optional SVC type)
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
//
package reliable

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
)

var (
	expectedCookie = uint64(0xde00ad01be02ef03)
)

const (
	// DefaultDispPath contains the system default for a dispatcher socket.
	DefaultDispPath = "/run/shm/dispatcher/default.sock"
	defBufSize      = 1 << 18
)

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
		writeBuffer:    make([]byte, defBufSize),
		writeStreamer:  NewWriteStreamer(conn),
		readBuffer:     make([]byte, defBufSize),
		readPacketizer: NewReadPacketizer(conn),
	}
}

// Dial connects to the UNIX socket specified by address.
func Dial(address string) (*Conn, error) {
	return DialTimeout(address, 0)
}

// DialTimeout acts like Dial but takes a timeout.
//
// A timeout of 0 means infinite timeout.
//
// To check for timeout errors, type assert the returned error to *net.OpError and
// call method Timeout().
func DialTimeout(address string, timeout time.Duration) (*Conn, error) {
	var err error
	var c net.Conn
	c, err = net.DialTimeout("unix", address, timeout)
	if err != nil {
		return nil, err
	}
	return newConn(c), nil
}

// Register connects to a SCION Dispatcher's UNIX socket.
// Future messages for address public or bind in AS ia which arrive at the dispatcher can be
// read by calling Read on the returned Conn structure.
func Register(dispatcher string, ia addr.IA, public *addr.AppAddr, bind *overlay.OverlayAddr,
	svc addr.HostSVC) (*Conn, uint16, error) {

	return RegisterTimeout(dispatcher, ia, public, bind, svc, time.Duration(0))
}

// RegisterTimeout acts like Register but takes a timeout.
//
// A timeout of 0 means infinite timeout.
//
// To check for timeout errors, type assert the returned error to *net.OpError and
// call method Timeout().
func RegisterTimeout(dispatcher string, ia addr.IA, public *addr.AppAddr,
	bind *overlay.OverlayAddr, svc addr.HostSVC, timeout time.Duration) (*Conn, uint16, error) {

	publicUDP, err := createUDPAddrFromAppAddr(public)
	if err != nil {
		return nil, 0, err
	}

	var bindUDP *net.UDPAddr
	if bind != nil {
		bindUDP = bind.ToUDPAddr()
	}
	reg := &Registration{
		IA:            ia,
		PublicAddress: publicUDP,
		BindAddress:   bindUDP,
		SVCAddress:    svc,
	}

	// Compute deadline prior to Dial, because timeout is relative to current time.
	deadline := time.Now().Add(timeout)
	conn, err := DialTimeout(dispatcher, timeout)
	if err != nil {
		return nil, 0, err
	}
	// If a timeout was specified, make reads and writes return if deadline exceeded.
	if timeout != 0 {
		conn.SetDeadline(deadline)
	}

	b := make([]byte, 1500)
	n, err := reg.SerializeTo(b)
	if err != nil {
		conn.Close()
		return nil, 0, err
	}
	_, err = conn.WriteTo(b[:n], nil)
	if err != nil {
		conn.Close()
		return nil, 0, err
	}

	n, _, err = conn.ReadFrom(b)
	if err != nil {
		conn.Close()
		return nil, 0, err
	}

	var c Confirmation
	err = c.DecodeFromBytes(b[:n])
	if err != nil {
		conn.Close()
		return nil, 0, err
	}
	// Disable deadline to not affect calling code
	conn.SetDeadline(time.Time{})
	return conn, c.Port, nil
}

// ReadFrom works similarly to Read. In addition to Read, it also returns the last hop
// (usually, the border router) which sent the message.
func (conn *Conn) ReadFrom(buf []byte) (int, net.Addr, error) {
	conn.readMutex.Lock()
	defer conn.readMutex.Unlock()

	n, err := conn.readPacketizer.Read(conn.readBuffer)
	if err != nil {
		return 0, nil, err
	}
	var p OverlayPacket
	p.DecodeFromBytes(conn.readBuffer[:n])
	var overlayAddr *overlay.OverlayAddr
	if p.Address != nil {
		var err error
		overlayAddr, err = overlay.NewOverlayAddr(
			addr.HostFromIP(p.Address.IP),
			addr.NewL4UDPInfo(uint16(p.Address.Port)),
		)
		if err != nil {
			return 0, nil, common.NewBasicError("overlay error", err)
		}
	}
	if len(buf) < len(p.Payload) {
		return 0, nil, common.NewBasicError("buffer too small", nil)
	}
	copy(buf, p.Payload)
	return len(p.Payload), overlayAddr, nil
}

// WriteTo blocks until it sends buf as a single framed message through conn.
// The ReliableSocket message header will contain the address and port information in dst.
// On error, the number of bytes returned is meaningless. On success, the number of bytes
// is always len(buf).
func (conn *Conn) WriteTo(buf []byte, dst net.Addr) (int, error) {
	conn.writeMutex.Lock()
	defer conn.writeMutex.Unlock()

	var publicAddress *net.UDPAddr
	if dst != nil {
		overlayAddr := dst.(*overlay.OverlayAddr)
		if overlayAddr != nil {
			publicAddress = overlayAddr.ToUDPAddr()
		}
	}
	p := &OverlayPacket{
		Address: publicAddress,
		Payload: buf,
	}
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
		return nil, common.NewBasicError("Unable to listen on address", err, "addr", laddr)
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

func createUDPAddrFromAppAddr(address *addr.AppAddr) (*net.UDPAddr, error) {
	if address == nil || address.L3 == nil {
		return nil, common.NewBasicError("nil application address", nil)
	}
	if address.L3.Type() != addr.HostTypeIPv4 && address.L3.Type() != addr.HostTypeIPv6 {
		return nil, common.NewBasicError("unsupported application address type", nil,
			"type", address.L3.Type())
	}
	var port int
	if address.L4 != nil {
		if address.L4.Type() != common.L4UDP {
			return nil, common.NewBasicError("bad L4 type", nil, "type", address.L4.Type())
		}
		port = int(address.L4.Port())
	}
	ip := address.L3.IP()
	if ip == nil {
		panic("inconsistent app address, ip should never be nil")
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}
