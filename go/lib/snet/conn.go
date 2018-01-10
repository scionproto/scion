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

package snet

import (
	"net"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
)

const (
	// Receive and send buffer sizes
	BufSize = 1<<16 - 1
)

type Error interface {
	error
	SCMP() *scmp.Hdr
}

var _ Error = (*OpError)(nil)

type OpError struct {
	scmp *scmp.Hdr
}

func (e *OpError) SCMP() *scmp.Hdr {
	return e.scmp
}

func (e *OpError) Error() string {
	return e.scmp.String()
}

var _ net.Conn = (*Conn)(nil)
var _ net.PacketConn = (*Conn)(nil)

type Conn struct {
	conn *reliable.Conn
	// Local, remote and bind SCION addresses (IA, L3, L4)
	laddr *Addr
	raddr *Addr
	baddr *Addr
	// svc address
	svc addr.HostSVC
	// Describes L3 and L4 protocol; currently only udp4 is implemented
	net        string
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	recvBuffer common.RawBytes
	sendBuffer common.RawBytes
	// Pointer to slice of paths updated by continous lookups; these are
	// used by default when creating a connection via Dial
	sp *pathmgr.SyncPaths
	// Reference to SCION networking context
	scionNet *Network
	// Key of last used path, used to select the same path for the next packet
	prefPathKey pathmgr.PathKey
}

// DialSCION calls DialSCION on the default networking context.
func DialSCION(network string, laddr, raddr *Addr) (*Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.DialSCION(network, laddr, raddr)
}

// DialSCIONWithBindSVC calls DialSCIONWithBindSVC on the default networking context.
func DialSCIONWithBindSVC(network string, laddr, raddr, baddr *Addr,
	svc addr.HostSVC) (*Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.DialSCIONWithBindSVC(network, laddr, raddr, baddr, svc)
}

// ListenSCION calls ListenSCION on the default networking context.
func ListenSCION(network string, laddr *Addr) (*Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.ListenSCION(network, laddr)
}

// ListenSCIONWithBindSVC calls ListenSCIONWithBindSVC on the default networking context.
func ListenSCIONWithBindSVC(network string, laddr, baddr *Addr, svc addr.HostSVC) (*Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.ListenSCIONWithBindSVC(network, laddr, baddr, svc)
}

// ReadFromSCION reads data into b, returning the length of copied data and the
// address of the sender. If the remote address for the connection is already
// known, ReadFromSCION returns an error.
func (c *Conn) ReadFromSCION(b []byte) (int, *Addr, error) {
	return c.read(b, true)
}

func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.read(b, true)
}

// Read reads data into b from a connection with a fixed remote address. If the
// remote address for the connection is unknown, Read returns an error.
func (c *Conn) Read(b []byte) (int, error) {
	n, _, err := c.read(b, false)
	return n, err
}

// read returns the number of bytes read, the address that sent the bytes and
// an error (if one occurred).
func (c *Conn) read(b []byte, from bool) (int, *Addr, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	var err error
	var remote *Addr
	if c.scionNet == nil {
		return 0, nil, common.NewBasicError("SCION network not initialized", nil)
	}
	n, lastHop, err := c.conn.ReadFrom(c.recvBuffer)
	if err != nil {
		return 0, nil, common.NewBasicError("Dispatcher read error", err)
	}
	if !from {
		lastHop = nil
	}
	pkt := &spkt.ScnPkt{
		DstIA: &addr.ISD_AS{},
		SrcIA: &addr.ISD_AS{},
		Path:  &spath.Path{},
	}
	err = hpkt.ParseScnPkt(pkt, c.recvBuffer[:n])
	if err != nil {
		return 0, nil, common.NewBasicError("SCION packet parse error", err)
	}
	// Copy data, extract address
	n, err = pkt.Pld.WritePld(b)
	if err != nil {
		return 0, nil, common.NewBasicError("Unable to copy payload", err)
	}
	// On UDP4 network we can get either UDP traffic or SCMP messages
	if c.net == "udp4" {
		// Extract remote address
		remote = &Addr{
			IA:   pkt.SrcIA,
			Host: pkt.SrcHost,
		}
		// Extract path and last hop
		if lastHop != nil {
			path := pkt.Path
			if err = path.Reverse(); err != nil {
				return 0, nil,
					common.NewBasicError("Unable to reverse path on received packet", err)
			}
			remote.Path = path
			remote.NextHopHost = lastHop.Addr
			remote.NextHopPort = lastHop.Port
		}
		switch hdr := pkt.L4.(type) {
		case *l4.UDP:
			remote.L4Port = hdr.SrcPort
			return n, remote, nil
		case *scmp.Hdr:
			c.handleSCMP(hdr, pkt)
			return n, remote, &OpError{scmp: hdr}
		default:
			return n, remote, common.NewBasicError("Unexpected SCION L4 protocol", nil,
				"expected", "UDP or SCMP", "actual", pkt.L4.L4Type())
		}
	}
	return 0, nil, common.NewBasicError("Unknown network", nil, "net", c.net)
}

func (c *Conn) handleSCMP(hdr *scmp.Hdr, pkt *spkt.ScnPkt) {
	// Only handle revocations for now
	if hdr.Class == scmp.C_Path && hdr.Type == scmp.T_P_RevokedIF {
		c.handleSCMPRev(hdr, pkt)
	} else {
		log.Warn("Received unsupported SCMP message", "class", hdr.Class, "type", hdr.Type)
	}
}

func (c *Conn) handleSCMPRev(hdr *scmp.Hdr, pkt *spkt.ScnPkt) {
	scmpPayload, ok := pkt.Pld.(*scmp.Payload)
	if !ok {
		log.Error("Unable to type assert payload to SCMP payload", "type", common.TypeOf(pkt.Pld))
	}
	info, ok := scmpPayload.Info.(*scmp.InfoRevocation)
	if !ok {
		log.Error("Unable to type assert SCMP Info to SCMP Revocation Info",
			"type", common.TypeOf(scmpPayload.Info))
	}
	log.Info("Received SCMP revocation", "header", hdr.String(), "payload", scmpPayload.String())
	// Extract RevInfo buffer and send it to path manager
	c.scionNet.pathResolver.Revoke(info.RevToken)
}

// WriteToSCION sends b to raddr.
func (c *Conn) WriteToSCION(b []byte, raddr *Addr) (int, error) {
	if c.conn == nil {
		return 0, common.NewBasicError("Connection not initialized", nil)
	}
	n, err := c.write(b, raddr)
	if err != nil {
		return 0, common.NewBasicError("Dispatcher error", err)
	}
	return n, err
}

func (c *Conn) WriteTo(b []byte, raddr net.Addr) (int, error) {
	if c.raddr != nil {
		return 0, common.NewBasicError("Unable to WriteTo, remote address already set", nil)
	}
	sraddr, ok := raddr.(*Addr)
	if !ok {
		return 0, common.NewBasicError("Unable to write to non-SCION address", nil, "addr", raddr)
	}
	return c.WriteToSCION(b, sraddr)
}

// Write sends b through a connection with fixed remote address. If the remote
// address for the conenction is unknown, Write returns an error.
func (c *Conn) Write(b []byte) (int, error) {
	if c.raddr == nil {
		return 0, common.NewBasicError("Unable to Write, remote address not set", nil)
	}
	return c.WriteToSCION(b, c.raddr)
}

func (c *Conn) write(b []byte, raddr *Addr) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	var err error
	var path *spath.Path
	var nextHopHost addr.HostAddr
	var nextHopPort uint16
	// If src and dst are in the same AS, the path will be empty
	if !c.laddr.IA.Eq(raddr.IA) {
		if raddr.Path != nil && raddr.NextHopHost != nil && raddr.NextHopPort != 0 {
			path = raddr.Path
			nextHopHost = raddr.NextHopHost
			nextHopPort = raddr.NextHopPort
		} else {
			pathEntry, err := c.selectPathEntry(raddr)
			if err != nil {
				return 0, err
			}
			path = spath.New(pathEntry.Path.FwdPath)
			nextHopHost = pathEntry.HostInfo.Host()
			nextHopPort = pathEntry.HostInfo.Port
			err = path.InitOffsets()
			if err != nil {
				return 0, common.NewBasicError("Unable to initialize path", err)
			}
		}
	}

	// Prepare packet fields
	udpHdr := &l4.UDP{
		SrcPort: c.laddr.L4Port, DstPort: raddr.L4Port, TotalLen: uint16(l4.UDPLen + len(b)),
	}
	pkt := &spkt.ScnPkt{
		DstIA:   raddr.IA,
		SrcIA:   c.laddr.IA,
		DstHost: raddr.Host,
		SrcHost: c.laddr.Host,
		Path:    path,
		L4:      udpHdr,
		Pld:     common.RawBytes(b),
	}

	// Serialize packet to internal buffer
	n, err := hpkt.WriteScnPkt(pkt, c.sendBuffer)
	if err != nil {
		return 0, common.NewBasicError("Unable to serialize SCION packet", err)
	}

	// Construct overlay next-hop
	var appAddr reliable.AppAddr
	if path == nil {
		// Overlay next-hop is destination
		appAddr = reliable.AppAddr{
			Addr: pkt.DstHost,
			Port: overlay.EndhostPort}
	} else {
		// Overlay next-hop is contained in path
		appAddr = reliable.AppAddr{Addr: nextHopHost, Port: nextHopPort}
	}

	// Send message
	n, err = c.conn.WriteTo(c.sendBuffer[:n], appAddr)
	if err != nil {
		return 0, common.NewBasicError("Dispatcher write error", err)
	}

	return pkt.Pld.Len(), nil
}

func (c *Conn) selectPathEntry(raddr *Addr) (*sciond.PathReplyEntry, error) {
	var err error
	var pathSet pathmgr.AppPathSet
	// If the remote address is fixed, register source and destination for
	// continous path updates
	if c.raddr == nil {
		pathSet = c.scionNet.pathResolver.Query(c.laddr.IA, raddr.IA)
	} else {
		// Sanity check, as Dial already initializes this
		if c.sp == nil {
			c.sp, err = c.scionNet.pathResolver.Watch(c.laddr.IA, c.raddr.IA)
			if err != nil {
				return nil, common.NewBasicError("Unable to register src-dst IAs", err,
					"src", c.laddr.IA, "dst", raddr.IA)
			}
		}
		pathSet = c.sp.Load().APS
	}

	if len(pathSet) == 0 {
		return nil, common.NewBasicError("Path not found", nil,
			"srcIA", c.laddr.IA, "dstIA", raddr.IA)
	}

	// FIXME(scrye): A preferred path should be stored for each contacted
	// destination. Currently the code below only supports one, which means
	// that alternating sends between two remotes offers no guarantees on
	// the path ever being the same.
	path := pathSet.GetAppPath(c.prefPathKey)
	c.prefPathKey = path.Key()
	return path.Entry, nil
}

func (c *Conn) BindAddr() net.Addr {
	return c.baddr
}

func (c *Conn) BindSnetAddr() *Addr {
	return c.baddr
}

func (c *Conn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *Conn) LocalSnetAddr() *Addr {
	return c.laddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *Conn) RemoteSnetAddr() *Addr {
	return c.raddr
}

func (c *Conn) SVC() addr.HostSVC {
	return c.svc
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
