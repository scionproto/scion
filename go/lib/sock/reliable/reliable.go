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

// ReliableSocket common header message format:
//   8-bytes: COOKIE (0xde00ad01be02ef03)
//   1-byte: ADDR TYPE (NONE=0, IPv4=1, IPv6=2, SVC=3, UNIX=4)
//   4-byte: data length, in Little Endian byte order
//   var-byte: Destination address (0 bytes for SCIOND API)
//     +2-byte: If destination address not NONE, destination port
//   var-byte: Payload
//
// ReliableSocket registration message format:
//  13-bytes: [Common header with address type NONE]
//   1-byte: Command (bit mask with 0x02=SCMP enable, 0x01 always set)
//   1-byte: L4 Proto (IANA number)
//   4-bytes: ISD-AS
//   2-bytes: Registered port
//   1-byte: Address type
//   var-byte: Address

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

// MaxLength contains the maximum payload length for the ReliableSocket framing protocol.
const MaxLength = 2000

var cookie = []byte{0xde, 0x00, 0xad, 0x01, 0xbe, 0x02, 0xef, 0x03}

const (
	hdrLen           = 13
	regBaseHeaderLen = 9
	regCommandField  = 0x03
)

// Conn implements the ReliableSocket framing protocol over UNIX sockets.
type Conn struct {
	*net.UnixConn
}

// AppAddr is a L3 + L4 address container, it currently only supports UDP for L4.
type AppAddr struct {
	Addr addr.HostAddr
	Port uint16
}

// Dial connects to the UNIX socket specified by address.
func Dial(address string) (*Conn, error) {
	c, err := net.Dial("unix", address)
	if err != nil {
		return &Conn{}, common.NewError("Unable to connect", "address", address)
	}
	return &Conn{c.(*net.UnixConn)}, nil
}

// Register connects to a SCION Dispatcher listening on a UNIX socket specified by dispatcher.
// Future messages for address a in AS ia which arrive at the dispatcher can be read by
// calling Read on the returned Conn structure.
func Register(dispatcher string, ia *addr.ISD_AS, a AppAddr) (*Conn, error) {
	c, err := Dial(dispatcher)
	if err != nil {
		return c, common.NewError("Failed to dial", "err", err)
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

	binary.BigEndian.PutUint16(request[offset:offset+2], a.Port)
	offset += 2

	if a.Addr.Type() == addr.HostTypeNone {
		return c, common.NewError("Cannot register NoneType address")
	}
	request[offset] = byte(a.Addr.Type())
	offset++

	copy(request[offset:], a.Addr.Pack())

	_, err = c.Write(request)
	if err != nil {
		return c, err
	}

	// Read the registration confirmation
	reply := make([]byte, 2)
	n, err := c.Read(reply)
	if err != nil {
		return c, err
	}

	// TODO(scrye): Fix the dispatcher replying with ports in little-endian
	replyPort := binary.LittleEndian.Uint16(reply[0:n])

	if a.Port != replyPort {
		return c, common.NewError("Port mismatch when registering with dispatcher", "expected",
			a.Port, "actual", replyPort)
	}

	return c, nil
}

// Read blocks until it reads the next framed message payload from conn and stores it in b.
// b must be large enough to fit the entire message. No addressing data is returned,
// only the payload. On error, return value n is always 0 and may not contain the
// correct number of bytes read from the socket.
func (conn *Conn) Read(b []byte) (int, error) {
	n, _, err := conn.ReadFrom(b)
	if err != nil {
		return 0, err
	}

	return n, nil
}

// ReadFrom works similarly to Read. In addition to Read, it also returns the last hop
// (usually, the border router) which sent the message.
func (conn *Conn) ReadFrom(b []byte) (n int, br AppAddr, err error) {
	header := make([]byte, hdrLen)
	_, err = io.ReadFull(conn.UnixConn, header)
	if err != nil {
		return 0, br, err
	}

	offset := 0
	if bytes.Compare(header[offset:offset+len(cookie)], cookie) != 0 {
		return 0, br, common.NewError("Protocol desynchronized", "conn", conn)
	}
	offset += len(cookie)

	rcvdAddrType := addr.HostAddrType(header[offset])
	offset++

	// Force endianness (although endianness not explicit in SCIOND)
	length := binary.LittleEndian.Uint32(header[offset : offset+4])
	offset += 4

	// Skip address bytes
	switch rcvdAddrType {
	case addr.HostTypeNone:
		// Nothing to skip
	case addr.HostTypeIPv4, addr.HostTypeIPv6, addr.HostTypeSVC:
		addrLen, _ := addr.HostLen(rcvdAddrType)
		// Add 2 bytes for port
		skipBuf := make([]byte, addrLen+2)
		n, err = io.ReadFull(conn.UnixConn, skipBuf)
		if err != nil {
			return 0, br, err
		}

		br.Port = binary.LittleEndian.Uint16(skipBuf[addrLen : addrLen+2])
		// NOTE: ierr is used to avoid nil stored in interface issue
		var ierr *common.Error
		br.Addr, ierr = addr.HostFromRaw(skipBuf[0:addrLen], rcvdAddrType)
		if ierr != nil {
			return 0, br, common.NewError("Unable to parse address", "address", skipBuf[0:addrLen])
		}
	default:
		return 0, br, common.NewError("Unknown address type", "type", rcvdAddrType)
	}

	// Read the payload
	if length > uint32(len(b)) {
		return 0, br, common.NewError("Insufficient buffer size", "have", len(b), "need", length)
	}

	n, err = io.ReadFull(conn.UnixConn, b[:length])
	if err != nil {
		return 0, br, err
	}

	return n, br, nil
}

// Write blocks until it sends b as a single framed message through conn.
// On error, return value n is always 0 and may not contain the correct number of
// bytes written to the socket. On success, return value n is always len(b).
func (conn *Conn) Write(b []byte) (n int, err error) {
	a, _ := addr.HostFromRaw(nil, addr.HostTypeNone)
	return conn.WriteTo(b, AppAddr{Addr: a, Port: 0})
}

// WriteTo works similarly to Write. In addition to Write, the header of the message will
// contain the address and port information in br.
func (conn *Conn) WriteTo(b []byte, br AppAddr) (n int, err error) {
	if len(b) > MaxLength {
		return 0, common.NewError("Payload exceed max length", "len", len(b), "max", MaxLength)
	}

	var destLength int
	switch br.Addr.Type() {
	case addr.HostTypeNone:
	case addr.HostTypeIPv4, addr.HostTypeIPv6, addr.HostTypeSVC:
		// Add 2 bytes for L4 port
		destLength += br.Addr.Size() + 2
	default:
		return 0, fmt.Errorf("Unknown address type (%d)", br.Addr.Type())
	}

	header := make([]byte, hdrLen+destLength)
	offset := 0

	copy(header[offset:offset+len(cookie)], cookie)
	offset += len(cookie)

	header[offset] = byte(br.Addr.Type())
	offset++

	// TODO(scrye): fix endianness (SCIOND expects machine order)
	binary.LittleEndian.PutUint32(header[offset:offset+4], uint32(len(b)))
	offset += 4

	if br.Addr.Type() == addr.HostTypeIPv4 || br.Addr.Type() == addr.HostTypeIPv6 ||
		br.Addr.Type() == addr.HostTypeSVC {
		copy(header[offset:], br.Addr.Pack())
		offset += br.Addr.Size()

		// TODO(scrye): fix endianness (dispatcher expects machine order)
		binary.LittleEndian.PutUint16(header[offset:offset+2], br.Port)
		offset += 2
	}

	_, err = io.Copy(conn.UnixConn, bytes.NewReader(header))
	if err != nil {
		return 0, err
	}

	ntmp, err := io.Copy(conn.UnixConn, bytes.NewReader(b))
	return int(ntmp), err
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
		return &Listener{}, common.NewError("Unable to listen on address", "addr", laddr)
	}

	return &Listener{l.(*net.UnixListener)}, nil
}

// Accept returns sockets which implement the SCION ReliableSocket protocol for reading
// and writing.
func (listener *Listener) Accept() (*Conn, error) {
	c, err := listener.UnixListener.Accept()
	if err != nil {
		return &Conn{}, common.NewError("Unable to accept", "listener", listener)
	}

	return &Conn{c.(*net.UnixConn)}, nil
}

func (listener *Listener) String() string {
	return fmt.Sprintf("&{addr: %v}", listener.UnixListener.Addr())
}
