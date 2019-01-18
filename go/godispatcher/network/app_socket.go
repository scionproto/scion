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
	"fmt"
	"io"
	"net"

	"github.com/scionproto/scion/go/godispatcher/internal/registration"
	"github.com/scionproto/scion/go/godispatcher/internal/respool"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spkt"
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
	RoutingTable *IATable
	// OverlayConn is the network connection to which egress traffic is sent.
	OverlayConn net.PacketConn
}

// Handle passes conn off to a per-connection state handler.
func (h *AppConnManager) Handle(conn net.PacketConn) {
	ch := &AppConnHandler{
		Conn:         conn,
		RoutingTable: h.RoutingTable,
		OverlayConn:  h.OverlayConn,
		Logger:       log.Root().New("clientID", fmt.Sprintf("%p", conn)),
	}
	go func() {
		defer log.LogPanicAndExit()
		ch.Handle()
	}()
}

// AppConnHandler handles a single SCION application connection.
type AppConnHandler struct {
	RoutingTable *IATable
	// Conn is the local socket to which the application is connected.
	Conn net.PacketConn
	// OverlayConn is the network connection to which egress traffic is sent.
	OverlayConn net.PacketConn
	Logger      log.Logger
}

func (h *AppConnHandler) Handle() {
	h.Logger.Info("Accepted new client")
	defer h.Logger.Info("Closed client socket")
	defer h.Conn.Close()

	ref, tableEntry, err := h.doRegExchange()
	if err != nil {
		h.Logger.Warn("registration error", "err", err)
		return
	}
	defer ref.Free()

	go func() {
		defer log.LogPanicAndExit()
		h.RunRingToAppDataplane(tableEntry.appIngressRing)
	}()
	h.RunAppToNetDataplane(ref)
}

func (h *AppConnHandler) doRegExchange() (registration.UDPReference, *TableEntry, error) {
	b := respool.GetBuffer()
	defer respool.PutBuffer(b)

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
	h.logRegistration(regInfo.IA, udpRef.UDPAddr(), getBindIP(regInfo.BindAddress),
		regInfo.SVCAddress)
	return udpRef, tableEntry, nil
}

func (h *AppConnHandler) logRegistration(ia addr.IA, public *net.UDPAddr, bind net.IP,
	svc addr.HostSVC) {

	items := []interface{}{"ia", ia, "public", public}
	if bind != nil {
		items = append(items, "extra_bind", bind)
	}
	if svc != addr.SvcNone {
		items = append(items, "svc", svc)
	}
	h.Logger.Info("Client registered address", items...)
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
func (h *AppConnHandler) RunAppToNetDataplane(ref registration.UDPReference) {
	for {
		pkt := respool.GetPacket()
		// XXX(scrye): we don't release the reference on error conditions, and
		// let the GC take care of this situation as they should be fairly
		// rare.

		if err := pkt.DecodeFromReliableConn(h.Conn); err != nil {
			if err == io.EOF {
				h.Logger.Info("[app->network] EOF received from client")
			} else {
				h.Logger.Error("[app->network] Client connection error", "err", err)
			}
			return
		}

		if err := registerIfSCMPRequest(ref, &pkt.Info); err != nil {
			log.Warn("SCMP Request ID error, packet still sent", "err", err)
		}

		if err := pkt.SendOnConn(h.OverlayConn, pkt.OverlayRemote); err != nil {
			h.Logger.Error("[app->network] Overlay socket error", "err", err)
		}
		pkt.Free()
	}
}

func registerIfSCMPRequest(ref registration.UDPReference, packet *spkt.ScnPkt) error {
	if scmpHdr, ok := packet.L4.(*scmp.Hdr); ok {
		if !isSCMPGeneralRequest(scmpHdr) {
			return nil
		}
		if id := getSCMPGeneralID(packet); id != 0 {
			return ref.RegisterID(id)
		}
	}
	return nil
}

// RunRingToAppDataplane moves packets from the application's ingress ring to
// the application's socket.
func (h *AppConnHandler) RunRingToAppDataplane(r *ringbuf.Ring) {
	entries := make(ringbuf.EntryList, 1)
	for {
		n, _ := r.Read(entries, true)
		if n > 0 {
			pkt := entries[0].(*respool.Packet)
			overlayAddr, err := overlay.NewOverlayAddr(
				addr.HostFromIP(pkt.OverlayRemote.IP),
				addr.NewL4UDPInfo(uint16(pkt.OverlayRemote.Port)),
			)
			if err != nil {
				h.Logger.Warn("[network->app] Unable to encode overlay address.", "err", err)
				continue
			}
			if err := pkt.SendOnConn(h.Conn, overlayAddr); err != nil {
				h.Logger.Error("[network->app] App connection error.", "err", err)
				h.Conn.Close()
				return
			}
			pkt.Free()
		}
	}
}
