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

// MaxLength contains the maximum payload length for the ReliableSocket framing protocol.
const MaxLength = (1 << 16) - 1 - hdrLen

var cookie = []byte{0xde, 0x00, 0xad, 0x01, 0xbe, 0x02, 0xef, 0x03}

const (
	hdrLen           = 13
	regBaseHeaderLen = 9
	regCommandField  = 0x03
)

// AppAddr is a L3 + L4 address container, it currently only supports UDP for L4.
type AppAddr struct {
	Addr addr.HostAddr
	Port uint16
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

// Register connects to a SCION Dispatcher listening on a UNIX socket specified by dispatcher.
// Future messages for address a in AS ia which arrive at the dispatcher can be read by
// calling Read on the returned Conn structure.
//
// ReliableSocket registration message format:
//  13-bytes: [Common header with address type NONE]
//   1-byte: Command (bit mask with 0x02=SCMP enable, 0x01 always set)
//   1-byte: L4 Proto (IANA number)
//   4-bytes: ISD-AS
//   2-bytes: Registered port
//   1-byte: Address type
//   var-byte: Address
func Register(dispatcher string, ia *addr.ISD_AS, a AppAddr) (*Conn, error) {
	if a.Addr.Type() == addr.HostTypeNone {
		return nil, common.NewError("Cannot register with NoneType address")
	}

	conn, err := Dial(dispatcher)
	if err != nil {
		return nil, common.NewError("Failed to dial", "err", err)
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
	common.Order.PutUint16(request[offset:offset+2], a.Port)
	offset += 2
	if a.Addr.Type() == addr.HostTypeNone {
		return nil, common.NewError("Cannot register NoneType address")
	}
	request[offset] = byte(a.Addr.Type())
	offset++
	copy(request[offset:], a.Addr.Pack())

	_, err = conn.Write(request)
	if err != nil {
		return nil, err
	}

	// Read the registration confirmation
	reply := make([]byte, 2)
	read, err := conn.Read(reply)
	if err != nil {
		return nil, err
	}

	replyPort := common.Order.Uint16(reply[0:read])
	if a.Port != replyPort {
		return nil, common.NewError("Port mismatch when registering with dispatcher", "expected",
			a.Port, "actual", replyPort)
	}
	return conn, nil
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
func (conn *Conn) ReadFrom(buf []byte) (int, AppAddr, error) {
	var lastHop AppAddr
	var read int

	header := make([]byte, hdrLen)
	_, err := io.ReadFull(conn.UnixConn, header)
	if err != nil {
		return 0, lastHop, err
	}
	offset := 0
	if bytes.Compare(header[offset:offset+len(cookie)], cookie) != 0 {
		return 0, lastHop, common.NewError("ReliableSock protocol desynchronized", "conn", conn)
	}
	offset += len(cookie)
	rcvdAddrType := addr.HostAddrType(header[offset])
	offset++
	// TODO(scrye): fix endianness
	length := HostOrder.Uint32(header[offset : offset+4])
	offset += 4

	// Skip address bytes
	switch rcvdAddrType {
	case addr.HostTypeNone:
		// Nothing to skip
	case addr.HostTypeIPv4, addr.HostTypeIPv6, addr.HostTypeSVC:
		addrLen, _ := addr.HostLen(rcvdAddrType)
		// Add 2 bytes for port
		addrBuf := make([]byte, addrLen+2)
		read, err = io.ReadFull(conn.UnixConn, addrBuf)
		if err != nil {
			return 0, lastHop, err
		}
		// TODO(scrye): Fix endianness
		lastHop.Port = HostOrder.Uint16(addrBuf[addrLen : addrLen+2])
		// NOTE: ierr is used to avoid nil stored in interface issue
		var ierr *common.Error
		lastHop.Addr, ierr = addr.HostFromRaw(addrBuf[0:addrLen], rcvdAddrType)
		if ierr != nil {
			return 0, lastHop, common.NewError("Unable to parse address", "address",
				addrBuf[0:addrLen])
		}
	default:
		return 0, lastHop, common.NewError("Unknown address type", "type", rcvdAddrType)
	}

	// Read the payload
	if length > uint32(len(buf)) {
		return 0, lastHop, common.NewError("Insufficient buffer size", "have", len(buf),
			"need", length)
	}
	read, err = io.ReadFull(conn.UnixConn, buf[:length])
	if err != nil {
		return 0, lastHop, err
	}
	return read, lastHop, nil
}

// Write blocks until it sends buf as a single framed message through conn.
// On error, the number of bytes returned is meaningless. On success, the number
// of bytes is always len(buf).
//
// ReliableSocket common header message format:
//   8-bytes: COOKIE (0xde00ad01be02ef03)
//   1-byte: ADDR TYPE (NONE=0, IPv4=1, IPv6=2, SVC=3, UNIX=4)
//   4-byte: data length, in Little Endian byte order
//   var-byte: Destination address (0 bytes for SCIOND API)
//     +2-byte: If destination address not NONE, destination port
//   var-byte: Payload
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
		// Add 2 bytes for L4 port
		destLength += dst.Addr.Size() + 2
	default:
		return 0, common.NewError("Unknown address type", "type", dst.Addr.Type())
	}

	header := make([]byte, hdrLen+destLength)
	offset := 0
	copy(header[offset:offset+len(cookie)], cookie)
	offset += len(cookie)
	header[offset] = byte(dst.Addr.Type())
	offset++
	// TODO(scrye): fix endianness (SCIOND expects host byte order)
	HostOrder.PutUint32(header[offset:offset+4], uint32(len(buf)))
	offset += 4
	if dst.Addr.Type() == addr.HostTypeIPv4 || dst.Addr.Type() == addr.HostTypeIPv6 ||
		dst.Addr.Type() == addr.HostTypeSVC {
		copy(header[offset:], dst.Addr.Pack())
		offset += dst.Addr.Size()
		// TODO(scrye): fix endianness (dispatcher expects host byte order)
		HostOrder.PutUint16(header[offset:offset+2], dst.Port)
		offset += 2
	}

	_, err := io.Copy(conn.UnixConn, bytes.NewReader(header))
	if err != nil {
		return 0, err
	}
	written, err := io.Copy(conn.UnixConn, bytes.NewReader(buf))
	if err != nil {
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
