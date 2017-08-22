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

// Package snet implements interfaces net.Conn and net.PacketConn for SCION
// connections.
//
// The default (package-wide) SCION network must first be initialized by
// calling Init. All future package scoped DialSCION and ListenSCION calls will
// use this initial context to get the local ISD-AS, dispatcher or sciond.
//
// A connection can be created by calling DialSCION or ListenSCION; both
// functions register an address-port pair with the local dispatcher. For Dial,
// the remote address is fixed, meaning only Read and Write can be used.
// Attempting to ReadFrom or WriteTo a connection created by Dial is an invalid
// operation. For Listen, the remote address cannot be fixed. ReadFrom,
// ReadFromSCION can be used to read from the connection and find out the
// sender's address; WriteTo and WriteToSCION can be used to send a message to
// a chosen destination.
//
// For applications that need to run in multiple ASes, new networking contexts
// can be created using NewNetwork. Calling the DialSCION or ListenSCION
// methods on the networking context yields connections that run in that context.
//
// Multiple networking contexts can share the same SCIOND and/or dispatcher.
package snet

import (
	"net"
	"sync"
	"time"

	cache "github.com/patrickmn/go-cache"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/hpkt"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/pathmgr"
	"github.com/netsec-ethz/scion/go/lib/sock/reliable"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
)

const (
	// Receive and send buffer sizes
	BufSize = 1<<16 - 1
)

var (
	// Time between checks for stale path references
	pathCleanupInterval = time.Minute
	// TTL for pointers to Path Resolver managed paths
	pathTTL = 30 * time.Minute
)

var _ net.Conn = &Conn{}
var _ net.PacketConn = &Conn{}

type Conn struct {
	dispMutex sync.Mutex
	conn      *reliable.Conn
	// Local and remote SCION addresses (IA, L3, L4)
	laddr *Addr
	raddr *Addr
	// Describes L3 and L4 protocol; currently only udp4 is implemented
	net        string
	recvBuffer common.RawBytes
	sendBuffer common.RawBytes
	// Reference to SCION networking context
	scionNet *Network
	// Cache of pointers to fresh path data
	// (map[string]*pathmgr.SyncPaths).  Because connections created by
	// Listen do not have a persistent remote address, we need to grab
	// paths for all encountered destinations. If a destination hasn't been
	// recently used, we delete the reference to its paths.
	pathMap *cache.Cache
}

// DialSCION returns a SCION connection to raddr. If laddr is not nil, it is
// registered with the local dispatcher for returning traffic. If laddr is nil,
// a random port is registered with the dispatcher. Parameter network must be
// "udp4". The returned connection's Read and Write methods can be used to
// receive and send SCION packets.
func DialSCION(network string, laddr, raddr *Addr) (*Conn, error) {
	if pkgNetwork == nil {
		return nil, common.NewError("SCION network not initialized")
	}
	return pkgNetwork.DialSCION(network, laddr, raddr)
}

// ListenSCION registers laddr with the dispatcher. If laddr is nil, then a
// random port is selected by the dispatcher. The LocalAddr method of the
// returned Conn can be used to discover the port. The returned connection's
// ReadFrom and WriteTo methods can be used to receive and send SCION packets
// with per-packet addressing. Parameter network must be "udp4".
func ListenSCION(network string, laddr *Addr) (*Conn, error) {
	if pkgNetwork == nil {
		return nil, common.NewError("SCION network not initialized")
	}
	return pkgNetwork.ListenSCION(network, laddr)
}

// ReadFromSCION reads data into b, returning the length of copied data and the
// address of the sender. If the remote address for the connection is already
// known, ReadFromSCION returns an error.
func (c *Conn) ReadFromSCION(b []byte) (int, *Addr, error) {
	if c.scionNet == nil {
		return 0, nil, common.NewError("SCION network not initialized")
	}
	n, a, err := c.read(b)
	if err != nil {
		return 0, nil, common.NewError("Dispatcher error", "err", err)
	}
	return n, a, err
}

func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.ReadFromSCION(b)
}

// Read reads data into b from a connection with a fixed remote address. If the remote address
// for the connection is unknown, Read returns an error.
func (c *Conn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFromSCION(b)
	return n, err
}

func (c *Conn) read(b []byte) (int, *Addr, error) {
	var cerr *common.Error
	var remote *Addr

	c.dispMutex.Lock()
	n, err := c.conn.Read(c.recvBuffer)
	c.dispMutex.Unlock()
	if err != nil {
		return 0, nil, common.NewError("Dispatcher read error", "err", err)
	}

	pkt := &spkt.ScnPkt{
		DstIA: &addr.ISD_AS{},
		SrcIA: &addr.ISD_AS{},
		Path:  &spath.Path{},
	}
	err = hpkt.ParseScnPkt(pkt, c.recvBuffer[:n])
	if err != nil {
		return 0, nil, common.NewError("SCION packet parse error", "err", err)
	}

	// Copy data, extract address
	n, cerr = pkt.Pld.Write(b)
	if cerr != nil {
		return 0, nil, common.NewError("Unable to copy payload", "err", cerr)
	}

	// Assert L4 as UDP header if local net is udp4
	if c.net == "udp4" {
		udpHdr, ok := pkt.L4.(*l4.UDP)
		if !ok {
			return 0, nil, common.NewError("Invalid L4 protocol",
				"expected", c.net, "actual", pkt.L4)
		}
		// Extract remote address
		remote = &Addr{
			IA:   pkt.SrcIA,
			Host: pkt.SrcHost,
			Port: udpHdr.SrcPort}
	}
	return n, remote, nil
}

// WriteToSCION sends b to raddr. If the remote address for the connection is
// already known, WriteToSCION returns an error.
func (c *Conn) WriteToSCION(b []byte, raddr *Addr) (int, error) {
	if c.scionNet == nil {
		return 0, common.NewError("SCION network not initialized")
	}
	if c.laddr == nil {
		return 0, common.NewError("Local address not set")
	}

	n, err := c.write(b, raddr)
	if err != nil {
		return 0, common.NewError("Dispatcher error", "err", err)
	}

	return n, err
}

func (c *Conn) WriteTo(b []byte, raddr net.Addr) (int, error) {
	if c.raddr != nil {
		return 0, common.NewError("Unable to WriteTo, remote address already set")
	}
	sraddr, ok := raddr.(*Addr)
	if !ok {
		return 0, common.NewError("Unable to write to non-SCION address",
			"addr", raddr)
	}
	return c.WriteToSCION(b, sraddr)
}

// Write sends b through a connection with fixed remote address. If the remote
// address for the conenction is unknown, Write returns an error.
func (c *Conn) Write(b []byte) (int, error) {
	if c.raddr == nil {
		return 0, common.NewError("Unable to Write, remote address not set")
	}
	return c.WriteToSCION(b, c.raddr)
}

func (c *Conn) write(b []byte, raddr *Addr) (int, error) {
	var sp *pathmgr.SyncPaths
	var err error
	// Check if srcIA-dstIA registered with path resolver
	iaKey := c.laddr.IA.String() + "." + raddr.IA.String()
	spGeneric, ok := c.pathMap.Get(iaKey)
	if !ok {
		sp, err = c.scionNet.pathResolver.Register(c.laddr.IA, raddr.IA)
		if err != nil {
			return 0, common.NewError("Unable to register src-dst IAs",
				"src", c.laddr.IA, "dst", raddr.IA, "err", err)
		}
		c.pathMap.Set(iaKey, sp, cache.DefaultExpiration)
	} else {
		sp = spGeneric.(*pathmgr.SyncPaths)
	}

	paths := sp.Load()
	if len(paths) == 0 {
		return 0, common.NewError("No path available",
			"src", c.laddr.IA, "dst", raddr.IA)
	}

	path := &spath.Path{
		Raw:    paths[0].Path.FwdPath,
		InfOff: 0,
		HopOff: 0}

	// Create the packet using initial IF/HF pointers
	hopIdx, err := resetHopIdx(path)
	if err != nil {
		return 0, common.NewError("Unable to initialize path", "err", err)
	}
	path.HopOff = common.LineLen * int(hopIdx)

	udpHdr := &l4.UDP{SrcPort: c.laddr.Port,
		DstPort:  raddr.Port,
		TotalLen: uint16(l4.UDPLen + len(b))}
	pkt := &spkt.ScnPkt{
		DstIA:   raddr.IA,
		SrcIA:   c.laddr.IA,
		DstHost: raddr.Host,
		SrcHost: c.laddr.Host,
		Path:    path,
		L4:      udpHdr,
		Pld:     common.RawBytes(b)}

	// Write packet to internal buffer
	n, err := hpkt.WriteScnPkt(pkt, c.sendBuffer)
	if err != nil {
		return 0, common.NewError("Unable to serialize SCION packet", "err", err)
	}

	// Write to dispatcher using the first path
	appAddr := reliable.AppAddr{
		Addr: addr.HostFromIP(paths[0].HostInfo.Addrs.Ipv4),
		Port: paths[0].HostInfo.Port}
	c.dispMutex.Lock()
	n, err = c.conn.WriteTo(c.sendBuffer[:n], appAddr)
	c.dispMutex.Unlock()
	if err != nil {
		return 0, common.NewError("Dispatcher write error", "err", err)
	}

	return pkt.Pld.Len(), nil
}

func (c *Conn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

// Compute initial hopIdx for a newly created packet
func resetHopIdx(path *spath.Path) (uint8, error) {
	var cerr *common.Error
	var infoF *spath.InfoField
	var hopF *spath.HopField
	fwdPath := path.Raw
	hopIdx := 1

	if infoF, cerr = spath.InfoFFromRaw(fwdPath); cerr != nil {
		return 0, cerr
	}
	maxHopIdx := int(infoF.Hops)
	if hopF, cerr = spath.HopFFromRaw(fwdPath[hopIdx*common.LineLen:]); cerr != nil {
		return 0, cerr
	}

	if infoF.Up && hopF.Xover {
		hopIdx += 1
		if hopIdx > maxHopIdx {
			return 0, common.NewError("Skipped entire path segment",
				"hopIdx", hopIdx, "maxHopIdx", maxHopIdx)
		}
	}

	for {
		if hopF, cerr = spath.HopFFromRaw(fwdPath[hopIdx*common.LineLen:]); cerr != nil {
			return 0, cerr
		}
		if hopF.VerifyOnly {
			hopIdx += 1
			if hopIdx > maxHopIdx {
				return 0, common.NewError("Skipped entire path segment",
					"hopIdx", hopIdx, "maxHopIdx", maxHopIdx)
			}
			continue
		}
		break
	}
	return uint8(hopIdx), nil
}
