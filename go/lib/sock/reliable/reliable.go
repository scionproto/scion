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
	"net"
	"time"

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
	defBufSize      = 1 << 18
)

type Msg struct {
	Buffer []byte
	Copied int
	Addr   *AppAddr
}

// Conn implements the ReliableSocket framing protocol over UNIX sockets.
type Conn struct {
	*net.UnixConn
	sendBuf       []byte
	recvBuf       []byte
	recvReadHead  int
	recvWriteHead int
}

// DialTimeout acts like Dial but takes a timeout.
//
// A negative timeout means infinite timeout.
//
// To check for timeout errors, type assert the returned error to *net.OpError and
// call method Timeout().
func DialTimeout(address string, timeout time.Duration) (*Conn, error) {
	var err error
	var c net.Conn
	if timeout < 0 {
		c, err = net.Dial("unix", address)
	} else {
		c, err = net.DialTimeout("unix", address, timeout)
	}
	if err != nil {
		return nil, err
	}
	return newConn(c), nil
}

// Dial connects to the UNIX socket specified by address.
func Dial(address string) (*Conn, error) {
	return DialTimeout(address, time.Duration(-1))
}

func newConn(c net.Conn) *Conn {
	return &Conn{
		UnixConn: c.(*net.UnixConn),
		sendBuf:  make([]byte, defBufSize),
		recvBuf:  make([]byte, defBufSize),
	}
}

// RegisterTimeout acts like Register but takes a timeout.
//
// A negative timeout means infinite timeout.
//
// To check for timeout errors, type assert the returned error to *net.OpError and
// call method Timeout().
func RegisterTimeout(dispatcher string, ia *addr.ISD_AS, a AppAddr,
	timeout time.Duration) (*Conn, uint16, error) {
	if a.Addr.Type() == addr.HostTypeNone {
		return nil, 0, common.NewCError("Cannot register with NoneType address")
	}

	deadline := time.Now().Add(timeout)
	conn, err := DialTimeout(dispatcher, timeout)
	if err != nil {
		return nil, 0, err
	}

	// If a timeout was specified, make reads and writes return if deadline exceeded
	if timeout != 0 {
		conn.SetDeadline(deadline)
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
	a.writePort(request[offset : offset+2])
	offset += 2
	if a.Addr.Type() == addr.HostTypeNone {
		conn.Close()
		return nil, 0, common.NewCError("Cannot register NoneType address")
	}
	request[offset] = byte(a.Addr.Type())
	offset++
	a.writeAddr(request[offset:])

	_, err = conn.Write(request)
	if err != nil {
		conn.Close()
		return nil, 0, err
	}
	// Read the registration confirmation
	reply := make([]byte, 2)
	read, err := conn.Read(reply)
	if err != nil {
		conn.Close()
		return nil, 0, err
	}
	replyPort := common.Order.Uint16(reply[:read])
	if a.Port != 0 && a.Port != replyPort {
		conn.Close()
		return nil, 0, common.NewCError("Port mismatch when registering with dispatcher",
			"expected", a.Port, "actual", replyPort)
	}

	// Disable deadline to not affect calling code
	conn.SetDeadline(time.Time{})
	return conn, replyPort, nil
}

// Register connects to a SCION Dispatcher's UNIX socket.
// Future messages for address a in AS ia which arrive at the dispatcher can be read by
// calling Read on the returned Conn structure.
func Register(dispatcher string, ia *addr.ISD_AS, a AppAddr) (*Conn, uint16, error) {
	return RegisterTimeout(dispatcher, ia, a, time.Duration(0))
}

// Read blocks until it reads the next framed message payload from conn and stores it in buf.
// The first return value contains the number of payload bytes read.
// buf must be large enough to fit the entire message. No addressing data is returned,
// only the payload. On error, the number of bytes returned is meaningless.
func (conn *Conn) Read(buf []byte) (int, error) {
	n, _, err := conn.ReadFrom(buf)
	return n, err
}

// ReadFrom works similarly to Read. In addition to Read, it also returns the last hop
// (usually, the border router) which sent the message.
func (conn *Conn) ReadFrom(buf []byte) (int, *AppAddr, error) {
	msgs := make([]Msg, 1)
	msgs[0].Buffer = buf
	_, err := conn.ReadN(msgs)
	if err != nil {
		return 0, nil, err
	}
	return msgs[0].Copied, msgs[0].Addr, nil
}

// ReadN is an extension of Read that allows callers to receive multiple
// messages from a ReliableSocket using a reduced number of system calls. ReadN
// copies data sequentially over each buf slice contained in msgs, blocking
// until at least one packet has been read. The function returns immediately if
// at least one packet has been read and the next one is not yet available.
// Each buffer contains a full packet (similarly to datagram oriented
// protocols).  ReadN returns the number of packets read. For each packet, the
// copied field of the Msg struct contains the number of bytes in the read
// packet.
func (conn *Conn) ReadN(msgs []Msg) (int, error) {
	fillIndex := 0
	// If we do not have enough data for a full packet, try a blocking read
	for fillIndex < len(msgs) {
		ok, err := conn.copyNextPacket(&msgs[fillIndex])
		if err != nil {
			return fillIndex, err
		}
		if ok {
			// Try to get another packet
			fillIndex += 1
			continue
		}
		// Not enough data to return another full packet.  Leftover
		// fragment data might exist, move it to start of buffer
		nCopied := copy(conn.recvBuf, conn.recvBuf[conn.recvReadHead:conn.recvWriteHead])
		conn.recvReadHead = 0
		conn.recvWriteHead = nCopied
		// If we grabbed at least one packet, we can return the results
		// immediately
		if fillIndex > 0 {
			return fillIndex, nil
		}
		// If we cannot return at least one packet, block to read more
		// data and try again
		nRead, err := conn.UnixConn.Read(conn.recvBuf[conn.recvWriteHead:])
		if err != nil {
			return 0, err
		}
		conn.recvWriteHead += nRead
	}
	// We read all the requested messages
	return fillIndex, nil
}

func (conn *Conn) copyNextPacket(msg *Msg) (bool, error) {
	var lastHop *AppAddr
	var err error
	var addrLen int
	// Peek to see if packet complete
	peekData := conn.recvBuf[conn.recvReadHead:conn.recvWriteHead]
	peekOffset := 0
	if len(peekData) < hdrLen {
		// Incomplete header, we can stop looking for more packets
		return false, nil
	}
	header := peekData[:hdrLen]
	if bytes.Compare(header[:len(cookie)], cookie) != 0 {
		conn.Close()
		return false, common.NewCError("ReliableSock protocol desynchronized", "conn", conn)
	}
	peekOffset += len(cookie)
	rcvdAddrType := addr.HostAddrType(header[peekOffset])
	peekOffset += 1
	length := int(common.Order.Uint32(header[peekOffset:]))
	peekOffset += 4

	// Read first hop address
	switch rcvdAddrType {
	case addr.HostTypeNone:
		// No first hop
	case addr.HostTypeIPv4, addr.HostTypeIPv6, addr.HostTypeSVC:
		addrLenU8, _ := addr.HostLen(rcvdAddrType)
		addrLen = int(addrLenU8)
		// Look at 2 additional bytes for port
		if len(peekData) < peekOffset+addrLen+2 {
			return false, nil
		}
		addrBuf := peekData[peekOffset : peekOffset+addrLen+2]
		lastHop, err = AppAddrFromRaw(addrBuf, rcvdAddrType)
		if err != nil {
			conn.Close()
			return false, common.NewCError("Unable to parse received address", "err", err)
		}
		peekOffset += addrLen + 2
	default:
		conn.Close()
		return false, common.NewCError("Unsupported address type", "type", rcvdAddrType)
	}

	// Read the payload
	if len(peekData) < peekOffset+length {
		return false, nil
	}
	n := copy(msg.Buffer, peekData[peekOffset:peekOffset+length])
	msg.Copied = n
	msg.Addr = lastHop
	conn.recvReadHead += peekOffset + length
	return true, nil
}

// Write blocks until it sends buf as a single framed message through conn.
// On error, the number of bytes returned is meaningless. On success, the number
// of bytes is always len(buf).
func (conn *Conn) Write(buf []byte) (int, error) {
	return conn.WriteTo(buf, NilAppAddr)
}

// WriteTo works similarly to Write. In addition to Write, the ReliableSocket message header
// will contain the address and port information in dst.
func (conn *Conn) WriteTo(buf []byte, dst AppAddr) (int, error) {
	msgs := make([]Msg, 1)
	msgs[0].Buffer = buf
	msgs[0].Addr = &dst
	for {
		n, err := conn.WriteN(msgs)
		if err != nil {
			return 0, err
		}
		if n > 0 {
			// FIXME(scrye): if the message was succesfully written,
			// we want to return from the function. If the message
			// could not be written, repeatedly try to write until
			// it works. This is far from optimal, but we will rarely
			// block on writes anyway.
			break
		}
	}
	return len(buf), nil
}

// WriteN is an extension of Write that allows callers to send multiple
// messages through a ReliableSocket using a reduced number of system calls.
// WriteN copies data sequentially from each buf slice contained in msgs.
// Destination address information can be specified in the addr field of each
// message. If the address is nil, then a HostTypeNone address is assumed. The
// function copies as many message as it can fit inside its internal buffer and
// then flushes those messages to the underlying socket in as few syscalls as
// possible.  Each buffer is copied in its entirety (similarly to datagram
// oriented protocols); the copied field of struct Msg is reset to 0 for
// written packets.  WriteN returns the number of packets written.
func (conn *Conn) WriteN(bufs []Msg) (int, error) {
	copiedMsgs := 0
	index := 0
	for i := range bufs {
		indexNew, copiedMsgsNew, err := conn.copyMsg(&bufs[i], index, copiedMsgs)
		if err != nil {
			return 0, err
		}
		if copiedMsgsNew == copiedMsgs {
			// No space for another message
			break
		}
		index = indexNew
		copiedMsgs = copiedMsgsNew
	}
	// Flush everything, we'll rarely block on writes anyway
	copied := 0
	for copied < index {
		n, err := conn.UnixConn.Write(conn.sendBuf[copied:index])
		if err != nil {
			return 0, common.NewCError("Error writing to UNIX socket", "err", err)
		}
		copied += n
	}
	return copiedMsgs, nil
}

// WriteNAll is a helper function that repeatedly blocks until all messages in
// bufs are sent on the underlying socket. WriteNAll returns the number of
// written messages; on success, this is equal to len(bufs).
func (conn *Conn) WriteNAll(bufs []Msg) (int, error) {
	for copied := 0; copied < len(bufs); {
		n, err := conn.WriteN(bufs[copied:])
		copied += n
		if err != nil {
			return copied, err
		}
	}
	return len(bufs), nil
}

func (conn *Conn) String() string {
	return fmt.Sprintf("&{laddr: %v, raddr: %v}", conn.UnixConn.LocalAddr(),
		conn.UnixConn.RemoteAddr())
}

// copyMsg returns the new index and copied messsages count on success.
func (conn *Conn) copyMsg(msg *Msg, index, copiedMsgs int) (int, int, error) {
	var dst *AppAddr
	if msg.Addr == nil {
		dst = &NilAppAddr
	} else {
		dst = msg.Addr
	}
	destLen := dst.Len()
	// If we do not have enough space for another message, break
	if len(conn.sendBuf[index:]) < hdrLen+destLen+len(msg.Buffer) {
		if copiedMsgs == 0 {
			// We are unable to fit the first message in the buffer
			return 0, 0, common.NewCError("Unable to copy first message",
				"details", "message too large", "bufSize",
				len(conn.sendBuf[index:]), "want",
				hdrLen+destLen+len(msg.Buffer))
		}
		return index, copiedMsgs, nil
	}
	// Cookie
	index += copy(conn.sendBuf[index:], cookie)
	// Addr type
	conn.sendBuf[index] = byte(dst.Addr.Type())
	index++
	// Payload length
	common.Order.PutUint32(conn.sendBuf[index:], uint32(len(msg.Buffer)))
	index += 4
	// Addr bytes
	dst.Write(conn.sendBuf[index:])
	index += dst.Len()
	// Payload
	index += copy(conn.sendBuf[index:], msg.Buffer)

	copiedMsgs += 1
	// Messages are always copied in their entirety. To avoid errors,
	// we reset the unused Copied field to 0
	msg.Copied = 0
	return index, copiedMsgs, nil
}

// Listener listens on Unix sockets and returns Conn sockets on Accept().
type Listener struct {
	*net.UnixListener
}

// Listen listens on UNIX socket laddr.
func Listen(laddr string) (*Listener, error) {
	l, err := net.Listen("unix", laddr)
	if err != nil {
		return nil, common.NewCError("Unable to listen on address", "addr", laddr)
	}
	return &Listener{l.(*net.UnixListener)}, nil
}

// Accept returns sockets which implement the SCION ReliableSocket protocol for reading
// and writing.
func (listener *Listener) Accept() (*Conn, error) {
	c, err := listener.UnixListener.Accept()
	if err != nil {
		return nil, err
	}
	return newConn(c), nil
}

func (listener *Listener) String() string {
	return fmt.Sprintf("&{addr: %v}", listener.UnixListener.Addr())
}
