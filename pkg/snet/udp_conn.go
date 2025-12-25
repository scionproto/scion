// Copyright 2025 ETH Zurich
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

package snet

import (
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// UDPConn is a wrapper interface around *net.UDPConn.
// It exists so custom types can wrap or customize the standard *net.UDPConn methods.
type UDPConn interface {
	SyscallConn() (syscall.RawConn, error)
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	ReadFrom(b []byte) (int, net.Addr, error)
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error)
	ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error)
	ReadMsgUDPAddrPort(b []byte, oob []byte) (n int, oobn int, flags int, addr netip.AddrPort, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	WriteTo(b []byte, addr net.Addr) (int, error)
	WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error)
	WriteMsgUDPAddrPort(b []byte, oob []byte, addr netip.AddrPort) (n int, oobn int, err error)
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
	File() (f *os.File, err error)
}
