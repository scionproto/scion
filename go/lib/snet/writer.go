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
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/spkt"
)

type scionConnWriter struct {
	base *scionConnBase

	conn       net.PacketConn
	writeMutex sync.Mutex
	sendBuffer common.RawBytes
	pr         pathmgr.Resolver
	// Pointer to slice of paths updated by continuous lookups; these are
	// used by default when creating a connection via Dial on SCIOND-enabled
	// networks. For SCIOND-less operation, this is set to nil.
	sp *pathmgr.SyncPaths
	// Key of last used path, used to select the same path for the next packet
	prefPathKey spathmeta.PathKey
}

func newScionConnWriter(base *scionConnBase, pr pathmgr.Resolver,
	conn net.PacketConn) *scionConnWriter {

	return &scionConnWriter{
		base:       base,
		pr:         pr,
		sendBuffer: make(common.RawBytes, BufSize),
		conn:       conn,
	}
}

// WriteToSCION sends b to raddr.
func (c *scionConnWriter) WriteToSCION(b []byte, raddr *Addr) (int, error) {
	if c.conn == nil {
		return 0, common.NewBasicError("Connection not initialized", nil)
	}
	return c.write(b, raddr)
}

func (c *scionConnWriter) WriteTo(b []byte, raddr net.Addr) (int, error) {
	if c.base.raddr != nil {
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
func (c *scionConnWriter) Write(b []byte) (int, error) {
	if c.base.raddr == nil {
		return 0, common.NewBasicError("Unable to Write, remote address not set", nil)
	}
	return c.WriteToSCION(b, c.base.raddr)
}

func (c *scionConnWriter) write(b []byte, raddr *Addr) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	var err error
	path := raddr.Path
	nextHop := raddr.NextHop
	emptyPath := path == nil || len(path.Raw) == 0
	if !emptyPath && nextHop == nil {
		return 0, common.NewBasicError("NextHop required with Path", nil)
	}
	if !c.base.laddr.IA.Eq(raddr.IA) && emptyPath {
		if c.base.scionNet.pathResolver == nil {
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
	} else if c.base.laddr.IA.Eq(raddr.IA) && !emptyPath {
		// If src and dst are in the same AS, the path should be empty
		return 0, common.NewBasicError("Path should be nil when sending to local AS", err)
	}
	// Prepare packet fields
	udpHdr := &l4.UDP{
		SrcPort:  c.base.laddr.Host.L4.Port(),
		DstPort:  raddr.Host.L4.Port(),
		TotalLen: uint16(l4.UDPLen + len(b)),
	}
	pkt := &spkt.ScnPkt{
		DstIA:   raddr.IA,
		SrcIA:   c.base.laddr.IA,
		DstHost: raddr.Host.L3,
		SrcHost: c.base.laddr.Host.L3,
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
func (c *scionConnWriter) selectPathEntry(raddr *Addr) (*sciond.PathReplyEntry, error) {
	var pathSet spathmeta.AppPathSet
	if assert.On {
		assert.Must(c.base.scionNet.pathResolver != nil, "must run with SCIOND for path selection")
	}
	// If the remote address is fixed, register source and destination for
	// continous path updates
	if c.base.raddr == nil {
		pathSet = c.base.scionNet.pathResolver.Query(context.TODO(), c.base.laddr.IA, raddr.IA)
	} else {
		pathSet = c.sp.Load().APS
	}

	if len(pathSet) == 0 {
		return nil, common.NewBasicError("Path not found", nil,
			"srcIA", c.base.laddr.IA, "dstIA", raddr.IA)
	}

	// FIXME(scrye): A preferred path should be stored for each contacted
	// destination. Currently the code below only supports one, which means
	// that alternating sends between two remotes offers no guarantees on
	// the path ever being the same.
	path := pathSet.GetAppPath(c.prefPathKey)
	c.prefPathKey = path.Key()
	return path.Entry, nil
}

func (c *scionConnWriter) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
