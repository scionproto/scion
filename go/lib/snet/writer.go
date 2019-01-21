// Copyright 2018 ETH Zurich
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
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/snet/internal/ctxmonitor"
	"github.com/scionproto/scion/go/lib/snet/internal/pathsource"
	"github.com/scionproto/scion/go/lib/spkt"
)

// Possible write errors
const (
	ErrNoAddr               = "remote address required, but none set"
	ErrDuplicateAddr        = "remote address specified as argument, but address set in conn"
	ErrAddressIsNil         = "address is nil"
	ErrNoApplicationAddress = "SCION host address is missing"
	ErrExtraPath            = "path set, but none required for local AS"
	ErrBadOverlay           = "overlay address not set, and construction from SCION address failed"
	ErrMustHavePath         = "overlay address set, but no path set"
	ErrPath                 = "no path set, and error during path resolution"
)

const (
	DefaultPathQueryTimeout = 5 * time.Second
)

type scionConnWriter struct {
	base *scionConnBase
	conn net.PacketConn

	mtx      sync.Mutex
	buffer   common.RawBytes
	resolver *remoteAddressResolver
}

func newScionConnWriter(base *scionConnBase, pr pathmgr.Resolver,
	conn net.PacketConn) *scionConnWriter {

	return &scionConnWriter{
		base:   base,
		buffer: make(common.RawBytes, BufSize),
		conn:   conn,
		resolver: &remoteAddressResolver{
			localIA:      base.laddr.IA,
			pathResolver: pathsource.NewPathSource(pr),
			monitor:      ctxmonitor.NewMonitor(),
		},
	}
}

// WriteToSCION sends b to raddr.
func (c *scionConnWriter) WriteToSCION(b []byte, raddr *Addr) (int, error) {
	return c.write(b, raddr)
}

func (c *scionConnWriter) WriteTo(b []byte, raddr net.Addr) (int, error) {
	sraddr, ok := raddr.(*Addr)
	if !ok {
		return 0, common.NewBasicError("Unable to write to non-SCION address", nil, "addr", raddr)
	}
	return c.WriteToSCION(b, sraddr)
}

// Write sends b through a connection with fixed remote address. If the remote
// address for the connection is unknown, Write returns an error.
func (c *scionConnWriter) Write(b []byte) (int, error) {
	return c.write(b, nil)
}

func (c *scionConnWriter) write(b []byte, raddr *Addr) (int, error) {
	raddr, err := c.resolver.resolveAddrPair(c.base.raddr, raddr)
	if err != nil {
		return 0, err
	}
	return c.writeWithLock(b, raddr)
}

func (c *scionConnWriter) writeWithLock(b []byte, raddr *Addr) (int, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	pkt := &spkt.ScnPkt{
		DstIA:   raddr.IA,
		SrcIA:   c.base.laddr.IA,
		DstHost: raddr.Host.L3,
		SrcHost: c.base.laddr.Host.L3,
		Path:    raddr.Path,
		L4: &l4.UDP{
			SrcPort:  c.base.laddr.Host.L4.Port(),
			DstPort:  raddr.Host.L4.Port(),
			TotalLen: uint16(l4.UDPLen + len(b)),
		},
		Pld: common.RawBytes(b),
	}
	// Serialize packet to internal buffer
	n, err := hpkt.WriteScnPkt(pkt, c.buffer)
	if err != nil {
		return 0, common.NewBasicError("Unable to serialize SCION packet", err)
	}
	// Send message
	n, err = c.conn.WriteTo(c.buffer[:n], raddr.NextHop)
	if err != nil {
		return 0, common.NewBasicError("Dispatcher write error", err)
	}
	return pkt.Pld.Len(), nil
}

func (c *scionConnWriter) SetWriteDeadline(t time.Time) error {
	if err := c.conn.SetWriteDeadline(t); err != nil {
		return err
	}
	c.resolver.monitor.SetDeadline(t)
	return nil
}

// remoteAddressResolver validates the contents of a remote snet address,
// taking into account both the remote address that might be present on a conn
// object, and the remote address passed in as argument to WriteTo or
// WriteToSCION.
type remoteAddressResolver struct {
	// localIA is the local AS. Path and overlay resolution differs between
	// destinations residing in the local AS, and destinations residing in
	// other ASes.
	localIA addr.IA
	// pathResolver is a source of paths and overlay addresses for snet.
	pathResolver pathsource.PathSource
	// monitor tracks contexts created for sciond
	monitor ctxmonitor.Monitor
}

func (r *remoteAddressResolver) resolveAddrPair(connAddr, argAddr *Addr) (*Addr, error) {
	switch {
	case connAddr == nil && argAddr == nil:
		return nil, common.NewBasicError(ErrNoAddr, nil)
	case connAddr != nil && argAddr != nil:
		return nil, common.NewBasicError(ErrDuplicateAddr, nil)
	case connAddr != nil:
		return r.resolveAddr(connAddr)
	default:
		// argAddr != nil
		return r.resolveAddr(argAddr)
	}
}

func (r *remoteAddressResolver) resolveAddr(address *Addr) (*Addr, error) {
	if address == nil {
		return nil, common.NewBasicError(ErrAddressIsNil, nil)
	}
	if address.Host == nil {
		return nil, common.NewBasicError(ErrNoApplicationAddress, nil)
	}
	if r.localIA.Equal(address.IA) {
		return r.resolveLocalDestination(address)
	}
	return r.resolveRemoteDestination(address)
}

func (r *remoteAddressResolver) resolveLocalDestination(address *Addr) (*Addr, error) {
	if address.Path != nil {
		return nil, common.NewBasicError(ErrExtraPath, nil)
	}
	if address.NextHop == nil {
		return addOverlayFromScionAddress(address)
	}
	return address, nil
}

func (r *remoteAddressResolver) resolveRemoteDestination(address *Addr) (*Addr, error) {
	switch {
	case address.Path != nil && address.NextHop == nil:
		return nil, common.NewBasicError(ErrBadOverlay, nil)
	case address.Path == nil && address.NextHop != nil:
		return nil, common.NewBasicError(ErrMustHavePath, nil)
	case address.Path != nil:
		return address, nil
	default:
		return r.addPath(address)
	}
}

func (r *remoteAddressResolver) addPath(address *Addr) (*Addr, error) {
	var err error
	address = address.Copy()
	ctx, cancelF := r.monitor.WithTimeout(context.Background(), DefaultPathQueryTimeout)
	defer cancelF()
	address.NextHop, address.Path, err = r.pathResolver.Get(ctx, r.localIA, address.IA)
	if err != nil {
		return nil, common.NewBasicError(ErrPath, nil)
	}
	return address, nil
}

func addOverlayFromScionAddress(address *Addr) (*Addr, error) {
	var err error
	address = address.Copy()
	address.NextHop, err = overlay.NewOverlayAddr(address.Host.L3,
		addr.NewL4UDPInfo(overlay.EndhostPort))
	if err != nil {
		return nil, common.NewBasicError(ErrBadOverlay, err)
	}
	return address, nil
}
