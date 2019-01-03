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

package network

import (
	"io"
	"net"

	"github.com/scionproto/scion/go/godispatcher/internal/bufpool"
	"github.com/scionproto/scion/go/godispatcher/internal/registration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// AppSocketServer accepts new connections coming from SCION apps, and
// hands them off to the registration + dataplane handler.
type AppSocketServer struct {
	Listener    *reliable.Listener
	ConnManager *AppConnManager
}

func (s *AppSocketServer) Serve() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return err
		}
		pconn := conn.(net.PacketConn)
		s.ConnManager.Handle(pconn)
	}
}

// AppConnManager handles new connections coming from SCION applications.
type AppConnManager struct {
	RoutingTable registration.IATable
	// OverlayConn is the network connection to which egress traffic is sent.
	OverlayConn net.PacketConn
}

// Handle passes conn off to a per-connection state handler.
func (h *AppConnManager) Handle(conn net.PacketConn) {
	ch := &AppConnHandler{
		Conn:         conn,
		RoutingTable: h.RoutingTable,
		OverlayConn:  h.OverlayConn,
	}
	go func() {
		defer log.LogPanicAndExit()
		ch.Handle()
	}()
}

// AppConnHandler handles a single SCION application connection.
type AppConnHandler struct {
	RoutingTable registration.IATable
	// Conn is the local socket to which the application is connected.
	Conn net.PacketConn
	// OverlayConn is the network connection to which egress traffic is sent.
	OverlayConn net.PacketConn
}

func (h *AppConnHandler) Handle() {
	defer h.Conn.Close()

	ref, tableEntry, err := h.doRegExchange()
	if err != nil {
		log.Warn("registration error", "err", err)
		return
	}
	defer ref.Free()

	go func() {
		defer log.LogPanicAndExit()
		RunRingToAppDataplane(tableEntry.appIngressRing, h.Conn)
	}()
	RunAppToNetDataplane(h.Conn, h.OverlayConn, ref.UDPAddr())
}

func (h *AppConnHandler) doRegExchange() (registration.UDPReference, *TableEntry, error) {
	b := bufpool.Get()
	defer bufpool.Put(b)

	regInfo, err := h.recvRegistration(b)
	if err != nil {
		return nil, nil, common.NewBasicError("registration message error", nil, "err", err)
	}

	tableEntry := newTableEntry(h.Conn)
	ref, err := h.RoutingTable.Register(
		regInfo.IA,
		regInfo.PublicAddress,
		getBindIP(regInfo.BindAddress),
		regInfo.SVCAddress,
		tableEntry,
	)
	if err != nil {
		return nil, nil, common.NewBasicError("registration table error", nil, "err", err)
	}

	udpRef := ref.(registration.UDPReference)
	port := uint16(udpRef.UDPAddr().Port)
	if err := h.sendConfirmation(b, &reliable.Confirmation{Port: port}); err != nil {
		// Need to release stale state from the table
		ref.Free()
		return nil, nil, common.NewBasicError("confirmation message error", nil, "err", err)
	}
	return udpRef, tableEntry, nil
}

func (h *AppConnHandler) recvRegistration(b common.RawBytes) (*reliable.Registration, error) {
	n, _, err := h.Conn.ReadFrom(b)
	if err != nil {
		return nil, err
	}
	b = b[:n]

	var rm reliable.Registration
	if err := rm.DecodeFromBytes(b); err != nil {
		return nil, err
	}
	return &rm, nil
}

func (h *AppConnHandler) sendConfirmation(b common.RawBytes, c *reliable.Confirmation) error {
	n, err := c.SerializeTo(b)
	if err != nil {
		return err
	}
	b = b[:n]

	if _, err := h.Conn.WriteTo(b, nil); err != nil {
		return err
	}
	return nil
}

// RunAppToNetDataplane moves packets from the application's socket to the
// overlay socket.
func RunAppToNetDataplane(appConn, overlayConn net.PacketConn, client *net.UDPAddr) {
	for {
		b := bufpool.Get()
		n, nextHop, err := appConn.ReadFrom(b)
		if err != nil {
			if err == io.EOF {
				log.Info("app->network, EOF received from app", "app", client)
			} else {
				log.Error("app->network, app conn error", "err", err)
			}
			return
		}
		b = b[:n]

		if nextHop == nil {
			log.Warn("app->network, missing next hop, dropping packet")
			continue
		}

		_, err = overlayConn.WriteTo(b, nextHop.(*overlay.OverlayAddr).ToUDPAddr())
		if err != nil {
			log.Error("app->network, overlay conn error", "err", err)
		}
		bufpool.Put(b)
	}
}

// RunRingToAppDataplane moves packets from the application's ingress ring to
// the application's socket.
func RunRingToAppDataplane(r *ringbuf.Ring, conn net.PacketConn) {
	entries := make(ringbuf.EntryList, 1)
	for {
		n, _ := r.Read(entries, true)
		if n > 0 {
			pkt := entries[0].(*Packet)

			overlayAddr, err := overlay.NewOverlayAddr(
				addr.HostFromIP(pkt.OverlayRemote.IP),
				addr.NewL4UDPInfo(uint16(pkt.OverlayRemote.Port)),
			)
			if err != nil {
				log.Warn("network->app, unable to encode overlay address", "err", err)
				continue
			}
			_, err = conn.WriteTo(pkt.Data, overlayAddr)
			if err != nil {
				log.Error("network->app, app conn error", "err", err)
				conn.Close()
				return
			}
			bufpool.Put(pkt.buffer)
		}
	}
}

type TableEntry struct {
	conn           net.PacketConn
	appIngressRing *ringbuf.Ring
}

func newTableEntry(conn net.PacketConn) *TableEntry {
	// Construct application ingress ring buffer
	appIngressRing := ringbuf.New(128, nil, "", nil)
	return &TableEntry{
		conn:           conn,
		appIngressRing: appIngressRing,
	}
}

func getBindIP(address *net.UDPAddr) net.IP {
	if address == nil {
		return nil
	}
	return address.IP
}
