// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet/internal/ctxmonitor"
	"github.com/scionproto/scion/go/lib/topology/overlay"
)

// Possible write errors
const (
	ErrNoAddr        common.ErrMsg = "remote address required, but none set"
	ErrDuplicateAddr common.ErrMsg = "remote address specified as argument, " +
		"but address set in conn"
	ErrAddressIsNil         common.ErrMsg = "address is nil"
	ErrNoApplicationAddress common.ErrMsg = "SCION host address is missing"
	ErrExtraPath            common.ErrMsg = "path set, but none required for local AS"
	ErrBadOverlay           common.ErrMsg = "overlay address not set, " +
		"and construction from SCION address failed"
	ErrMustHavePath common.ErrMsg = "overlay address set, but no path set"
	ErrPath         common.ErrMsg = "no path set, and error during path resolution"
)

const (
	DefaultPathQueryTimeout = 5 * time.Second
)

type scionConnWriter struct {
	base     *scionConnBase
	conn     PacketConn
	resolver *remoteAddressResolver

	mtx    sync.Mutex
	buffer common.RawBytes
}

func newScionConnWriter(base *scionConnBase, querier PathQuerier,
	conn PacketConn) *scionConnWriter {

	return &scionConnWriter{
		base: base,
		conn: conn,
		resolver: &remoteAddressResolver{
			localIA:     base.scionNet.localIA,
			pathQuerier: querier,
			monitor:     ctxmonitor.NewMonitor(),
		},
		buffer: make(common.RawBytes, common.MaxMTU),
	}
}

// WriteToSCION sends b to raddr.
func (c *scionConnWriter) WriteToSCION(b []byte, raddr *Addr) (int, error) {
	return c.write(b, raddr)
}

func (c *scionConnWriter) WriteTo(b []byte, a net.Addr) (int, error) {
	switch addr := a.(type) {
	case *Addr:
		return c.WriteToSCION(b, addr)
	case *UDPAddr:
		return c.WriteToSCION(b, addr.ToAddr())
	case *SVCAddr:
		return c.WriteToSCION(b, addr.ToAddr())
	default:
		return 0, common.NewBasicError("Unable to write to non-SCION address", nil,
			"addr", fmt.Sprintf("%v(%T)", a, a))
	}
}

// Write sends b through a connection with fixed remote address. If the remote
// address for the connection is unknown, Write returns an error.
func (c *scionConnWriter) Write(b []byte) (int, error) {
	return c.write(b, nil)
}

func (c *scionConnWriter) write(b []byte, raddr *Addr) (int, error) {
	var connRemote *Addr
	if c.base.remote != nil {
		connRemote = c.base.remote.ToAddr()
	}
	raddr, err := c.resolver.ResolveAddrPair(connRemote, raddr)
	if err != nil {
		return 0, err
	}
	return c.writeWithLock(b, raddr)
}

func (c *scionConnWriter) writeWithLock(b []byte, raddr *Addr) (int, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	pkt := &SCIONPacket{
		Bytes: Bytes(c.buffer),
		SCIONPacketInfo: SCIONPacketInfo{
			Destination: SCIONAddress{IA: raddr.IA, Host: raddr.Host.L3},
			Source: SCIONAddress{IA: c.base.scionNet.localIA,
				Host: addr.HostFromIP(c.base.listen.IP)},
			Path: raddr.Path,
			L4Header: &l4.UDP{
				SrcPort:  uint16(c.base.listen.Port),
				DstPort:  raddr.Host.L4,
				TotalLen: uint16(l4.UDPLen + len(b)),
			},
			Payload: common.RawBytes(b),
		},
	}
	if err := c.conn.WriteTo(pkt, raddr.NextHop); err != nil {
		return 0, err
	}
	return len(b), nil
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
	pathQuerier PathQuerier
	// monitor tracks contexts created for sciond
	monitor ctxmonitor.Monitor
}

func (r *remoteAddressResolver) ResolveAddrPair(connAddr, argAddr *Addr) (*Addr, error) {
	switch {
	case connAddr == nil && argAddr == nil:
		return nil, common.NewBasicError(ErrNoAddr, nil)
	case connAddr != nil && argAddr != nil:
		return nil, common.NewBasicError(ErrDuplicateAddr, nil)
	case connAddr != nil:
		return r.ResolveAddr(connAddr)
	default:
		// argAddr != nil
		return r.ResolveAddr(argAddr)
	}
}

func (r *remoteAddressResolver) ResolveAddr(address *Addr) (*Addr, error) {
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
		return addOverlayFromScionAddress(address), nil
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
	paths, err := r.pathQuerier.Query(ctx, address.IA)
	if err != nil {
		return nil, serrors.Wrap(ErrPath, err)
	}
	if len(paths) == 0 {
		return nil, serrors.WithCtx(ErrPath, "reason", "no path found")
	}
	address.NextHop = paths[0].OverlayNextHop()
	address.Path = paths[0].Path()
	return address, nil
}

func addOverlayFromScionAddress(address *Addr) *Addr {
	address = address.Copy()
	address.NextHop = &net.UDPAddr{IP: address.Host.L3.IP(), Port: overlay.EndhostPort}
	return address
}
