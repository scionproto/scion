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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
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
	// Pointer to slice of paths updated by continuous lookups; these are
	// used by default when creating a connection via Dial on SCIOND-enabled
	// networks. For SCIOND-less operation, this is set to nil.
	sp *pathmgr.SyncPaths
	// Reference to SCION networking context
	scionNet *Network
	// Key of last used path, used to select the same path for the next packet
	prefPathKey spathmeta.PathKey
}

// DialSCION calls DialSCION with infinite timeout on the default networking
// context.
func DialSCION(network string, laddr, raddr *Addr) (*Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.DialSCION(network, laddr, raddr, 0)
}

// DialSCIONWithBindSVC calls DialSCIONWithBindSVC with infinite timeout on the
// default networking context.
func DialSCIONWithBindSVC(network string, laddr, raddr, baddr *Addr,
	svc addr.HostSVC) (*Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.DialSCIONWithBindSVC(network, laddr, raddr, baddr, svc, 0)
}

// ListenSCION calls ListenSCION with infinite timeout on the default
// networking context.
func ListenSCION(network string, laddr *Addr) (*Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.ListenSCION(network, laddr, 0)
}

// ListenSCIONWithBindSVC calls ListenSCIONWithBindSVC with infinite timeout on
// the default networking context.
func ListenSCIONWithBindSVC(network string, laddr, baddr *Addr, svc addr.HostSVC) (*Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.ListenSCIONWithBindSVC(network, laddr, baddr, svc, 0)
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
	n, lastHopNetAddr, err := c.conn.ReadFrom(c.recvBuffer)
	if err != nil {
		return 0, nil, common.NewBasicError("Dispatcher read error", err)
	}
	var lastHop *overlay.OverlayAddr
	if from {
		var ok bool
		lastHop, ok = lastHopNetAddr.(*overlay.OverlayAddr)
		if !ok {
			return 0, nil, common.NewBasicError("Invalid lastHop address Type", nil,
				"Actual", lastHopNetAddr)
		}
	}
	pkt := &spkt.ScnPkt{
		DstIA: addr.IA{},
		SrcIA: addr.IA{},
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
			Path: pkt.Path,
		}
		// Extract path
		if err = remote.Path.Reverse(); err != nil {
			return 0, nil, common.NewBasicError("Unable to reverse path on received packet", err)
		}
		// Extract last hop
		if lastHop != nil {
			// XXX When do we not get a lastHop?
			// Copy the address to prevent races. See
			// https://github.com/scionproto/scion/issues/1659.
			remote.NextHop = lastHop.Copy()
		}
		var err error
		var l4i addr.L4Info
		switch hdr := pkt.L4.(type) {
		case *l4.UDP:
			l4i = addr.NewL4UDPInfo(hdr.SrcPort)
		case *scmp.Hdr:
			l4i = addr.NewL4SCMPInfo()
			c.handleSCMP(hdr, pkt)
			err = &OpError{scmp: hdr}
		default:
			err = common.NewBasicError("Unexpected SCION L4 protocol", nil,
				"expected", "UDP or SCMP", "actual", pkt.L4.L4Type())
		}
		// Copy the address to prevent races. See
		// https://github.com/scionproto/scion/issues/1659.
		remote.Host = &addr.AppAddr{L3: pkt.SrcHost.Copy(), L4: l4i}
		return n, remote, err
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
	// If we have a path manager, extract RevInfo buffer and send it
	//
	// FIXME(scrye): this completely hides the revocation from the application.
	// This is problematic for applications that manage their own paths, as
	// they need to be informed that they should try to use a different one.
	if c.scionNet.pathResolver != nil {
		c.scionNet.pathResolver.Revoke(info.RawSRev)
	}
}

// WriteToSCION sends b to raddr.
func (c *Conn) WriteToSCION(b []byte, raddr *Addr) (int, error) {
	if c.conn == nil {
		return 0, common.NewBasicError("Connection not initialized", nil)
	}
	return c.write(b, raddr)
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
	path := raddr.Path
	nextHop := raddr.NextHop
	emptyPath := path == nil || len(path.Raw) == 0
	if !emptyPath && nextHop == nil {
		return 0, common.NewBasicError("NextHop required with Path", nil)
	}
	if !c.laddr.IA.Eq(raddr.IA) && emptyPath {
		if c.scionNet.pathResolver == nil {
			return 0, common.NewBasicError("Path required, but no path manager configured", nil)
		}

		pathEntry, err := c.selectPathEntry(raddr)
		if err != nil {
			return 0, err
		}
		path = spath.New(pathEntry.Path.FwdPath)
		nextHop, err = pathEntry.HostInfo.Overlay()
		if err != nil {
			return 0, common.NewBasicError("Unsupported Overlay Addr", err,
				"addr", pathEntry.HostInfo)
		}
		err = path.InitOffsets()
		if err != nil {
			return 0, common.NewBasicError("Unable to initialize path", err)
		}
	} else if c.laddr.IA.Eq(raddr.IA) && !emptyPath {
		// If src and dst are in the same AS, the path should be empty
		return 0, common.NewBasicError("Path should be nil when sending to local AS", err)
	}
	// Prepare packet fields
	udpHdr := &l4.UDP{
		SrcPort:  c.laddr.Host.L4.Port(),
		DstPort:  raddr.Host.L4.Port(),
		TotalLen: uint16(l4.UDPLen + len(b)),
	}
	pkt := &spkt.ScnPkt{
		DstIA:   raddr.IA,
		SrcIA:   c.laddr.IA,
		DstHost: raddr.Host.L3,
		SrcHost: c.laddr.Host.L3,
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
	if nextHop == nil {
		// Overlay next-hop is destination
		nextHop, err = overlay.NewOverlayAddr(pkt.DstHost, addr.NewL4UDPInfo(overlay.EndhostPort))
		if err != nil {
			return 0, common.NewBasicError("Bad overlay address", err, "Host", pkt.DstHost)
		}
	}
	// Send message
	n, err = c.conn.WriteTo(c.sendBuffer[:n], nextHop)
	if err != nil {
		return 0, common.NewBasicError("Dispatcher write error", err)
	}

	return pkt.Pld.Len(), nil
}

// selectPathEntry chooses a path to raddr. This must not be called if
// running SCIOND-less.
func (c *Conn) selectPathEntry(raddr *Addr) (*sciond.PathReplyEntry, error) {
	var pathSet spathmeta.AppPathSet
	if assert.On {
		assert.Must(c.scionNet.pathResolver != nil, "must run with SCIOND for path selection")
	}
	// If the remote address is fixed, register source and destination for
	// continous path updates
	if c.raddr == nil {
		pathSet = c.scionNet.pathResolver.Query(c.laddr.IA, raddr.IA)
	} else {
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
