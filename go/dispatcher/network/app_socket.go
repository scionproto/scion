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

	"github.com/scionproto/scion/go/dispatcher/dispatcher"
	"github.com/scionproto/scion/go/dispatcher/internal/metrics"
	"github.com/scionproto/scion/go/dispatcher/internal/respool"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// AppSocketServer accepts new connections coming from SCION apps, and
// hands them off to the registration + dataplane handler.
type AppSocketServer struct {
	Listener   *reliable.Listener
	DispServer *dispatcher.Server
}

func (s *AppSocketServer) Serve() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return err
		}
		pconn := conn.(net.PacketConn)
		s.Handle(pconn)
	}
}

// Handle passes conn off to a per-connection state handler.
func (h *AppSocketServer) Handle(conn net.PacketConn) {
	ch := &AppConnHandler{
		Conn:   conn,
		Logger: log.New("clientID", fmt.Sprintf("%p", conn)),
	}
	go func() {
		defer log.HandlePanic()
		ch.Handle(h.DispServer)
	}()
}

// AppConnHandler handles a single SCION application connection.
type AppConnHandler struct {
	// Conn is the local socket to which the application is connected.
	Conn     net.PacketConn
	DispConn *dispatcher.Conn
	Logger   log.Logger
}

func (h *AppConnHandler) Handle(appServer *dispatcher.Server) {
	h.Logger.Debug("Accepted new client")
	defer h.Logger.Debug("Closed client socket")
	defer h.Conn.Close()

	dispConn, err := h.doRegExchange(appServer)
	if err != nil {
		metrics.M.AppConnErrors().Inc()
		h.Logger.Info("Registration error", "err", err)
		return
	}
	h.DispConn = dispConn.(*dispatcher.Conn)
	defer h.DispConn.Close()
	svc := h.DispConn.SVCAddr().String()
	metrics.M.OpenSockets(metrics.SVC{Type: svc}).Inc()
	defer metrics.M.OpenSockets(metrics.SVC{Type: svc}).Dec()

	go func() {
		defer log.HandlePanic()
		h.RunRingToAppDataplane()
	}()

	h.RunAppToNetDataplane()
}

// doRegExchange manages an application's registration request, and returns a
// reference to registered data that should be freed at the end of the
// registration, information about allocated ring buffers and whether an error occurred.
func (h *AppConnHandler) doRegExchange(appServer *dispatcher.Server) (net.PacketConn, error) {

	b := respool.GetBuffer()
	defer respool.PutBuffer(b)

	regInfo, err := h.recvRegistration(b)
	if err != nil {
		return nil, serrors.New("registration message error", "err", err)
	}
	appConn, _, err := appServer.Register(nil,
		regInfo.IA, regInfo.PublicAddress, regInfo.SVCAddress)
	if err != nil {
		return nil, serrors.New("registration table error", "err", err)
	}
	udpAddr := appConn.(*dispatcher.Conn).LocalAddr().(*net.UDPAddr)
	port := uint16(udpAddr.Port)
	if err := h.sendConfirmation(b, &reliable.Confirmation{Port: port}); err != nil {
		appConn.Close()
		return nil, serrors.New("confirmation message error", "err", err)
	}
	h.logRegistration(regInfo.IA, udpAddr, getBindIP(regInfo.BindAddress),
		regInfo.SVCAddress)
	return appConn, nil
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
	h.Logger.Debug("Client registered address", items...)
}

func (h *AppConnHandler) recvRegistration(b []byte) (*reliable.Registration, error) {
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

func (h *AppConnHandler) sendConfirmation(b []byte, c *reliable.Confirmation) error {
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
// underlay socket.
func (h *AppConnHandler) RunAppToNetDataplane() {

	for {
		pkt := respool.GetPacket()
		// XXX(scrye): we don't release the reference on error conditions, and
		// let the GC take care of this situation as they should be fairly
		// rare.

		if err := pkt.DecodeFromReliableConn(h.Conn); err != nil {
			if err == io.EOF {
				h.Logger.Debug("[app->network] EOF received from client")
			} else {
				h.Logger.Debug("[app->network] Client connection error", "err", err)
				metrics.M.AppReadErrors().Inc()
			}
			return
		}
		metrics.M.AppReadBytes().Add(float64(pkt.Len()))
		metrics.M.AppReadPkts().Inc()

		n, err := h.DispConn.Write(pkt)
		if err != nil {
			metrics.M.NetWriteErrors().Inc()
			h.Logger.Error("[app->network] Underlay socket error", "err", err)
		} else {
			metrics.M.NetWriteBytes().Add(float64(n))
			metrics.M.NetWritePkts().Inc()
		}
		pkt.Free()
	}
}

// RunRingToAppDataplane moves packets from the application's ingress ring to
// the application's socket.
func (h *AppConnHandler) RunRingToAppDataplane() {
	for {
		pkt := h.DispConn.Read()
		if pkt == nil {
			// Ring was closed because app shut down its data socket
			return
		}
		n, err := pkt.SendOnConn(h.Conn, pkt.UnderlayRemote)
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

func getBindIP(address *net.UDPAddr) net.IP {
	if address == nil {
		return nil
	}
	return address.IP
}
