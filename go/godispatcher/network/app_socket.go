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

	"github.com/scionproto/scion/go/godispatcher/internal/metrics"
	"github.com/scionproto/scion/go/godispatcher/internal/registration"
	"github.com/scionproto/scion/go/godispatcher/internal/respool"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
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
	// IPv4OverlayConn is the network connection to which IPv4 egress traffic
	// is sent.
	IPv4OverlayConn net.PacketConn
	// IPv6OverlayConn is the network connection to which IPv6 egress traffic
	// is sent.
	IPv6OverlayConn net.PacketConn
}

// Handle passes conn off to a per-connection state handler.
func (h *AppConnManager) Handle(conn net.PacketConn) {
	ch := &AppConnHandler{
		Conn:            conn,
		RoutingTable:    h.RoutingTable,
		IPv4OverlayConn: h.IPv4OverlayConn,
		IPv6OverlayConn: h.IPv6OverlayConn,
		Logger:          log.Root().New("clientID", fmt.Sprintf("%p", conn)),
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
	// IPv4OverlayConn is the network connection to which egress IPv4 traffic
	// is sent.
	IPv4OverlayConn net.PacketConn
	// IPv6OverlayConn is the network connection to which egress IPv6 traffic
	// is sent.
	IPv6OverlayConn net.PacketConn
	Logger          log.Logger
}

func (h *AppConnHandler) Handle() {
	h.Logger.Info("Accepted new client")
	defer h.Logger.Info("Closed client socket")
	defer h.Conn.Close()

	ref, tableEntry, useIPv6, err := h.doRegExchange()
	if err != nil {
		metrics.M.AppConnErrors().Inc()
		h.Logger.Warn("registration error", "err", err)
		return
	}
	defer ref.Free()
	metrics.M.OpenSockets(metrics.SVC{Type: ref.SVCAddr().String()}).Inc()
	defer metrics.M.OpenSockets(metrics.SVC{Type: ref.SVCAddr().String()}).Dec()

	defer tableEntry.appIngressRing.Close()
	go func() {
		defer log.LogPanicAndExit()
		h.RunRingToAppDataplane(tableEntry.appIngressRing)
	}()

	conn := h.IPv4OverlayConn
	if useIPv6 {
		conn = h.IPv6OverlayConn
	}
	h.RunAppToNetDataplane(ref, conn)
}

// doRegExchange manages an application's registration request, and returns a
// reference to registered data that should be freed at the end of the
// registration, information about allocated ring buffers, a boolean specifying
// whether to use IPv6 egress instead of IPv4, and whether an error occurred.
func (h *AppConnHandler) doRegExchange() (registration.RegReference, *TableEntry, bool, error) {
	b := respool.GetBuffer()
	defer respool.PutBuffer(b)

	regInfo, err := h.recvRegistration(b)
	if err != nil {
		return nil, nil, false, common.NewBasicError("registration message error", nil, "err", err)
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
		return nil, nil, false, common.NewBasicError("registration table error", nil, "err", err)
	}

	udpRef := ref.(registration.RegReference)
	port := uint16(udpRef.UDPAddr().Port)
	if err := h.sendConfirmation(b, &reliable.Confirmation{Port: port}); err != nil {
		// Need to release stale state from the table
		ref.Free()
		return nil, nil, false, common.NewBasicError("confirmation message error", nil, "err", err)
	}
	h.logRegistration(regInfo.IA, udpRef.UDPAddr(), getBindIP(regInfo.BindAddress),
		regInfo.SVCAddress)
	isIPv6 := regInfo.PublicAddress.IP.To4() == nil
	return udpRef, tableEntry, isIPv6, nil
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
func (h *AppConnHandler) RunAppToNetDataplane(ref registration.RegReference,
	ovConn net.PacketConn) {

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
				metrics.M.AppReadErrors().Inc()
			}
			return
		}
		metrics.M.AppReadBytes().Add(float64(pkt.Len()))
		metrics.M.AppReadPkts().Inc()

		if err := registerIfSCMPRequest(ref, &pkt.Info); err != nil {
			log.Warn("SCMP Request ID error, packet still sent", "err", err)
		}

		n, err := pkt.SendOnConn(ovConn, pkt.OverlayRemote)
		if err != nil {
			metrics.M.NetWriteErrors().Inc()
			h.Logger.Error("[app->network] Overlay socket error", "err", err)
		} else {
			metrics.M.NetWriteBytes().Add(float64(n))
			metrics.M.NetWritePkts().Inc()
		}
		pkt.Free()
	}
}

// registerIfSCMPRequest registers the ID of the SCMP Request, if it is an
// SCMP::General::EchoRequest, SCMP::General::TraceRouteRequest or SCMP::General::RecordPathRequest
// packet. It also increments SCMP-related metrics.
func registerIfSCMPRequest(ref registration.RegReference, packet *spkt.ScnPkt) error {
	if scmpHdr, ok := packet.L4.(*scmp.Hdr); ok {
		metrics.M.SCMPWritePkts(
			metrics.SCMP{
				Class: scmpHdr.Class.String(),
				Type:  scmpHdr.Type.Name(scmpHdr.Class),
			},
		).Inc()
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
		if n < 0 {
			// Ring was closed because app shut down its data socket
			return
		}
		if n > 0 {
			pkt := entries[0].(*respool.Packet)
			n, err := pkt.SendOnConn(h.Conn, pkt.OverlayRemote)
			if err != nil {
				metrics.M.AppWriteErrors().Inc()
				h.Logger.Error("[network->app] App connection error.", "err", err)
				h.Conn.Close()
				return
			}
			metrics.M.AppWritePkts().Inc()
			metrics.M.AppWriteBytes().Add(float64(n))
			pkt.Free()
		}
	}
}
