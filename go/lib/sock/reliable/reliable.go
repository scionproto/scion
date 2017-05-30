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
//   1-byte: Command (bit mask with 0x02=SCMP enable, 0x01 always set)
//   1-byte: L4 Proto (IANA number)
//   4-bytes: ISD-AS
//   2-bytes: L4 port
//   1-byte: Address type
//   var-byte: Address
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
// The connections are not thread safe.
//
package reliable

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

var (
	cookie           = []byte{0xde, 0x00, 0xad, 0x01, 0xbe, 0x02, 0xef, 0x03}
	regBaseHeaderLen = len(cookie) + 1
	hdrLen           = regBaseHeaderLen + 4
	// MaxLength contains the maximum payload length for the ReliableSocket framing protocol.
	MaxLength = (1 << 16) - 1 - hdrLen
)

const (
	regCommandField = 0x03 // Register command (0x01) with SCMP enabled (0x02)
)

// AppAddr is a L3 + L4 address container, it currently only supports UDP for L4.
type AppAddr struct {
	Addr addr.HostAddr
	Port uint16
}

func (a *AppAddr) packAddr() []byte {
	return a.Addr.Pack()
}

func (a *AppAddr) packPort() []byte {
	if a.Addr.Type() == addr.HostTypeNone {
		return nil
	}
	buf := make([]byte, 2)
	common.Order.PutUint16(buf, a.Port)
	return buf
}

func (a *AppAddr) Pack() []byte {
	buf := make([]byte, 0, a.Len())
	buf = append(buf, a.packAddr()...)
	buf = append(buf, a.packPort()...)
	return buf
}

func ParseAppAddr(buf common.RawBytes, addrType addr.HostAddrType) (*AppAddr, error) {
	var a AppAddr
	// NOTE: cerr is used to avoid nil stored in interface issue
	var cerr *common.Error
	addrLen, cerr := addr.HostLen(addrType)
	if cerr != nil {
		return nil, cerr
	}
	// Add 2 for port
	if len(buf) < int(addrLen)+2 {
		return nil, common.NewError("Buffer too small for address type", "expected", addrLen+2,
			"actual", len(buf))
	}

	a.Addr, cerr = addr.HostFromRaw(buf, addrType)
	if cerr != nil {
		return nil, common.NewError("Unable to parse address", "address",
			buf[:addrLen], "type", addrType)
	}
	a.Port = common.Order.Uint16(buf[addrLen:])
	return &a, nil
}

func (a *AppAddr) Len() int {
	if a.Addr.Type() == addr.HostTypeNone {
		return a.Addr.Size()
	}
	return a.Addr.Size() + 2
}

// Conn implements the ReliableSocket framing protocol over UNIX sockets.
type Conn struct {
	*net.UnixConn
}

// Dial connects to the UNIX socket specified by address.
func Dial(address string) (*Conn, error) {
	c, err := net.Dial("unix", address)
	if err != nil {
		return nil, common.NewError("Unable to connect", "address", address)
	}
	return &Conn{c.(*net.UnixConn)}, nil
}

// Register connects to a SCION Dispatcher's UNIX socket.
// Future messages for address a in AS ia which arrive at the dispatcher can be read by
// calling Read on the returned Conn structure.
func Register(dispatcher string, ia *addr.ISD_AS, a AppAddr) (*Conn, uint16, error) {
	if a.Addr.Type() == addr.HostTypeNone {
		return nil, 0, common.NewError("Cannot register with NoneType address")
	}

	conn, err := Dial(dispatcher)
	if err != nil {
		return nil, 0, common.NewError("Failed to dial", "err", err)
	}

	request := make([]byte, regBaseHeaderLen+a.Addr.Size())
	offset := 0
	// Enable SCMP
	request[offset] = regCommandField
	offset++
	request[offset] = byte(common.L4UDP)
	offset++
	ia.Write(request[offset : offset+4])
	offset += 4
	copy(request[offset:offset+2], a.packPort())
	offset += 2
	if a.Addr.Type() == addr.HostTypeNone {
		conn.UnixConn.Close()
		return nil, 0, common.NewError("Cannot register NoneType address")
	}
	request[offset] = byte(a.Addr.Type())
	offset++
	copy(request[offset:], a.packAddr())

	_, err = conn.Write(request)
	if err != nil {
		conn.UnixConn.Close()
		return nil, 0, err
	}

	// Read the registration confirmation
	reply := make([]byte, 2)
	read, err := conn.Read(reply)
	if err != nil {
		conn.UnixConn.Close()
		return nil, 0, err
	}

	replyPort := common.Order.Uint16(reply[:read])
	if a.Port != 0 && a.Port != replyPort {
		conn.UnixConn.Close()
		return nil, 0, common.NewError("Port mismatch when registering with dispatcher", "expected",
			a.Port, "actual", replyPort)
	}
	return conn, replyPort, nil
}

// Read blocks until it reads the next framed message payload from conn and stores it in buf.
// The first return value contains the number of payload bytes read.
// buf must be large enough to fit the entire message. No addressing data is returned,
// only the payload. On error, the number of bytes returned is meaningless.
func (conn *Conn) Read(buf []byte) (int, error) {
	read, _, err := conn.ReadFrom(buf)
	if err != nil {
		return 0, err
	}
	return read, nil
}

// ReadFrom works similarly to Read. In addition to Read, it also returns the last hop
// (usually, the border router) which sent the message.
func (conn *Conn) ReadFrom(buf []byte) (int, *AppAddr, error) {
	var lastHop *AppAddr
	var read int

	header := make([]byte, hdrLen)
	_, err := io.ReadFull(conn.UnixConn, header)
	if err != nil {
		conn.UnixConn.Close()
		return 0, nil, err
	}
	if bytes.Compare(header[:len(cookie)], cookie) != 0 {
		conn.UnixConn.Close()
		return 0, nil, common.NewError("ReliableSock protocol desynchronized", "conn", conn)
	}
	offset := len(cookie)
	rcvdAddrType := addr.HostAddrType(header[offset])
	offset++
	length := common.Order.Uint32(header[offset : offset+4])

	// Read first hop address
	switch rcvdAddrType {
	case addr.HostTypeNone:
		// No first hop
	case addr.HostTypeIPv4, addr.HostTypeIPv6, addr.HostTypeSVC:
		addrLen, _ := addr.HostLen(rcvdAddrType)
		// Add 2 bytes for port
		addrBuf := make([]byte, addrLen+2)
		read, err = io.ReadFull(conn.UnixConn, addrBuf)
		if err != nil {
			conn.UnixConn.Close()
			return 0, nil, err
		}
		lastHop, err = ParseAppAddr(addrBuf, rcvdAddrType)
		if err != nil {
			conn.UnixConn.Close()
			return 0, nil, err
		}
	default:
		conn.UnixConn.Close()
		return 0, nil, common.NewError("Unknown address type", "type", rcvdAddrType)
	}

	// Read the payload
	if int(length) > len(buf) {
		conn.UnixConn.Close()
		return 0, nil, common.NewError("Insufficient buffer size", "have", len(buf),
			"need", length)
	}
	read, err = io.ReadFull(conn.UnixConn, buf[:length])
	if err != nil {
		conn.UnixConn.Close()
		return 0, nil, err
	}
	return read, lastHop, nil
}

// Write blocks until it sends buf as a single framed message through conn.
// On error, the number of bytes returned is meaningless. On success, the number
// of bytes is always len(buf).
func (conn *Conn) Write(buf []byte) (int, error) {
	a, _ := addr.HostFromRaw(nil, addr.HostTypeNone)
	return conn.WriteTo(buf, AppAddr{Addr: a, Port: 0})
}

// WriteTo works similarly to Write. In addition to Write, the ReliableSocket message header
// will contain the address and port information in dst.
func (conn *Conn) WriteTo(buf []byte, dst AppAddr) (int, error) {
	if len(buf) > MaxLength {
		return 0, common.NewError("Payload exceed max length", "len", len(buf), "max", MaxLength)
	}

	var destLength int
	switch dst.Addr.Type() {
	case addr.HostTypeNone:
	case addr.HostTypeIPv4, addr.HostTypeIPv6, addr.HostTypeSVC:
		destLength += dst.Len()
	default:
		return 0, common.NewError("Unknown address type", "type", dst.Addr.Type())
	}

	header := make([]byte, hdrLen+destLength)
	copy(header, cookie)
	offset := len(cookie)
	header[offset] = byte(dst.Addr.Type())
	offset++
	common.Order.PutUint32(header[offset:offset+4], uint32(len(buf)))
	offset += 4
	copy(header[offset:], dst.Pack())
	offset += dst.Len()

	_, err := io.Copy(conn.UnixConn, bytes.NewReader(header))
	if err != nil {
		conn.UnixConn.Close()
		return 0, err
	}
	written, err := io.Copy(conn.UnixConn, bytes.NewReader(buf))
	if err != nil {
		conn.UnixConn.Close()
		return 0, err
	}
	return int(written), nil
}

func (conn *Conn) String() string {
	return fmt.Sprintf("&{laddr: %v, raddr: %v}", conn.UnixConn.LocalAddr(),
		conn.UnixConn.RemoteAddr())
}

// Listener listens on Unix sockets and returns Conn sockets on Accept().
type Listener struct {
	*net.UnixListener
}

// Listen listens on UNIX socket laddr.
func Listen(laddr string) (*Listener, error) {
	l, err := net.Listen("unix", laddr)
	if err != nil {
		return nil, common.NewError("Unable to listen on address", "addr", laddr)
	}
	return &Listener{l.(*net.UnixListener)}, nil
}

// Accept returns sockets which implement the SCION ReliableSocket protocol for reading
// and writing.
func (listener *Listener) Accept() (*Conn, error) {
	c, err := listener.UnixListener.Accept()
	if err != nil {
		return nil, common.NewError("Unable to accept", "listener", listener)
	}
	return &Conn{c.(*net.UnixConn)}, nil
}

func (listener *Listener) String() string {
	return fmt.Sprintf("&{addr: %v}", listener.UnixListener.Addr())
}
