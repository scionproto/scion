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
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/overlay/conn"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// OverflowLoggingInterval is the minimum amount of time that needs to
// pass before another overflow logging message is printed (if needed).
const OverflowLoggingInterval = 10 * time.Second

// ReceiveBufferSize is the size of receive buffers used by the dispatcher.
const ReceiveBufferSize = 1 << 20

type Dispatcher struct {
	RoutingTable      *IATable
	OverlaySocket     string
	ApplicationSocket string
}

func (d *Dispatcher) ListenAndServe() error {
	metaLogger := &throttledMetaLogger{
		Logger:      log.Root(),
		MinInterval: OverflowLoggingInterval,
	}
	ipv4Conn, err := openConn("udp4", d.OverlaySocket, metaLogger)
	if err != nil {
		return err
	}
	defer ipv4Conn.Close()

	ipv6Conn, err := openConn("udp6", d.OverlaySocket, metaLogger)
	if err != nil {
		return err
	}
	defer ipv6Conn.Close()

	appServerConn, err := reliable.Listen(d.ApplicationSocket)
	if err != nil {
		return err
	}
	defer appServerConn.Close()

	errChan := make(chan error)
	go func() {
		defer log.LogPanicAndExit()
		netToRingDataplane := &NetToRingDataplane{
			OverlayConn:  ipv4Conn,
			RoutingTable: d.RoutingTable,
		}
		errChan <- netToRingDataplane.Run()
	}()
	go func() {
		defer log.LogPanicAndExit()
		netToRingDataplane := &NetToRingDataplane{
			OverlayConn:  ipv6Conn,
			RoutingTable: d.RoutingTable,
		}
		errChan <- netToRingDataplane.Run()
	}()

	go func() {
		defer log.LogPanicAndExit()
		appServer := &AppSocketServer{
			Listener: appServerConn,
			ConnManager: &AppConnManager{
				RoutingTable:    d.RoutingTable,
				IPv4OverlayConn: ipv4Conn,
				IPv6OverlayConn: ipv6Conn,
			},
		}
		errChan <- appServer.Serve()
	}()

	return <-errChan
}

// openConn opens an overlay socket that tracks additional socket information
// such as packets dropped due to buffer full.
//
// Note that Go-style dual-stacked IPv4/IPv6 connections are not supported. If
// network is udp, it will be treated as udp4.
func openConn(network, address string, p SocketMetaHandler) (net.PacketConn, error) {
	// We cannot allow the Go standard library to open both types of sockets
	// because the socket options are specific to only one socket type, so we
	// degrade udp to only udp4.
	if network == "udp" {
		network = "udp4"
	}
	listeningAddress, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, common.NewBasicError("unable to construct UDP addr", err)
	}

	var hostIP addr.HostAddr
	switch network {
	case "udp4":
		hostIP = addr.HostIPv4(listeningAddress.IP)
	case "udp6":
		hostIP = addr.HostIPv6(listeningAddress.IP)
	default:
		return nil, common.NewBasicError("unsupported network", nil, "network", network)
	}

	ov, err := overlay.NewOverlayAddr(
		hostIP,
		addr.NewL4UDPInfo(uint16(listeningAddress.Port)),
	)
	if err != nil {
		return nil, common.NewBasicError("unable to construct overlay address", err)
	}
	c, err := conn.New(ov, nil, &conn.Config{ReceiveBufferSize: ReceiveBufferSize})
	if err != nil {
		return nil, common.NewBasicError("unable to open conn", err)
	}

	return &overlayConnWrapper{Conn: c, Handler: p}, nil
}

// SocketMetaHandler processes OS socket metadata during reads.
type SocketMetaHandler interface {
	Handle(*conn.ReadMeta)
}

// throttledMetaLogger logs packets dropped due to full receive buffers,
// with a configurable threshold on how often logging messages are printed.
type throttledMetaLogger struct {
	// Logger is used to print the logging messages.
	Logger log.Logger
	// MinInterval is the minimum duration of time that has passed since the
	MinInterval time.Duration

	mu sync.Mutex
	// lastPrintTimestamp is the time when the previous logging message was
	// printed.
	lastPrintTimestamp time.Time
	// lastPrintValue is the overflow value printed in the last logging message.
	lastPrintValue int
}

func (p *throttledMetaLogger) Handle(m *conn.ReadMeta) {
	p.mu.Lock()
	if m.RcvOvfl > p.lastPrintValue && time.Since(p.lastPrintTimestamp) > p.MinInterval {
		p.Logger.Debug("Detected socket overflow", "total_cnt", m.RcvOvfl)
		p.lastPrintTimestamp = time.Now()
		p.lastPrintValue = m.RcvOvfl
	}
	p.mu.Unlock()
}

// overlayConnWrapper wraps a specialized overlay conn into a net.PacketConn
// implementation. Only *net.UDPAddr addressing is supported.
type overlayConnWrapper struct {
	// Conn is the wrapped overlay connection object.
	conn.Conn
	// Handler is used to customize how the connection treats socket
	// metadata.
	Handler SocketMetaHandler
}

func (o *overlayConnWrapper) ReadFrom(p []byte) (int, net.Addr, error) {
	n, meta, err := o.Conn.Read(common.RawBytes(p))
	if meta == nil {
		return n, nil, err
	}
	o.Handler.Handle(meta)
	return n, meta.Src.ToUDPAddr(), err
}

func (o *overlayConnWrapper) WriteTo(p []byte, a net.Addr) (int, error) {
	udpAddr, ok := a.(*net.UDPAddr)
	if !ok {
		return 0, common.NewBasicError("address is not UDP", nil, "addr", a)
	}
	ov, err := overlay.NewOverlayAddr(
		addr.HostFromIP(udpAddr.IP),
		addr.NewL4UDPInfo(uint16(udpAddr.Port)),
	)
	if err != nil {
		return 0, common.NewBasicError("unable to construct overlay address", err)
	}
	return o.Conn.WriteTo(common.RawBytes(p), ov)
}

func (o *overlayConnWrapper) Close() error {
	return o.Conn.Close()
}

func (o *overlayConnWrapper) LocalAddr() net.Addr {
	return o.Conn.LocalAddr().ToUDPAddr()
}

func (o *overlayConnWrapper) SetDeadline(t time.Time) error {
	return o.Conn.SetDeadline(t)
}

func (o *overlayConnWrapper) SetReadDeadline(t time.Time) error {
	return o.Conn.SetReadDeadline(t)
}

func (o *overlayConnWrapper) SetWriteDeadline(t time.Time) error {
	return o.Conn.SetWriteDeadline(t)
}
