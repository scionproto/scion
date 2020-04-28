// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package infraenv contains convenience function common to SCION infra
// services.
package infraenv

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
	"github.com/scionproto/scion/go/lib/svc"
)

const (
	ErrAppUnableToInitMessenger common.ErrMsg = "Unable to initialize SCION Infra Messenger"
)

var resolutionRequestPayload = []byte{0x00, 0x00, 0x00, 0x00}

// QUIC contains the QUIC configuration for control-plane speakers.
type QUIC struct {
	// Address is the UDP address to start the QUIC server on.
	Address string
	// CertFile is the certificate to use for QUIC authentication.
	CertFile string
	// KeyFile is the private key to use for QUIC authentication.
	KeyFile string
}

// NetworkConfig describes the networking configuration of a SCION
// control-plane RPC endpoint.
type NetworkConfig struct {
	// IA is the local AS number.
	IA addr.IA
	// Public is the Internet-reachable address in the case where the service
	// is behind NAT.
	Public *net.UDPAddr
	// SVC registers this server to receive packets with the specified SVC
	// destination address.
	SVC addr.HostSVC
	// ReconnectToDispatcher sets up sockets that automatically reconnect if
	// the dispatcher closes the connection (e.g., if the dispatcher goes
	// down).
	ReconnectToDispatcher bool
	// QUIC contains configuration details for QUIC servers. If the listening
	// address is the empty string, then no QUIC socket is opened.
	QUIC QUIC
	// SVCResolutionFraction can be used to customize whether SVC resolution is
	// enabled.
	SVCResolutionFraction float64
	// Router is used by various infra modules for path-related operations. A
	// nil router means only intra-AS traffic is supported.
	Router snet.Router
	// SVCRouter is used to discover the underlay addresses of intra-AS SVC
	// servers.
	SVCRouter messenger.LocalSVCRouter
}

// Messenger initializes a SCION control-plane RPC endpoint using the specified
// configuration.
func (nc *NetworkConfig) Messenger() (infra.Messenger, error) {
	var quicConn net.PacketConn
	var quicAddress string
	if nc.QUIC.Address != "" {
		var err error
		quicConn, err = nc.initQUICSocket()
		if err != nil {
			return nil, err
		}
		quicAddress = fmt.Sprintf("%s", quicConn.LocalAddr()) // assuming net.UDPAddr.
		log.Trace("QUIC conn initialized", "local_addr", quicAddress)
	}

	conn, err := nc.initUDPSocket(quicAddress)
	if err != nil {
		return nil, err
	}

	msgerCfg := &messenger.Config{
		IA:              nc.IA,
		AddressRewriter: nc.AddressRewriter(nil),
	}
	msgerCfg.Dispatcher = disp.New(
		conn,
		messenger.DefaultAdapter,
		log.Root(),
	)
	if nc.QUIC.Address != "" {
		var err error
		msgerCfg.QUIC, err = nc.buildQUICConfig(quicConn)
		if err != nil {
			return nil, err
		}
	}
	msger := messenger.New(msgerCfg)
	return msger, nil

}

// AddressRewriter initializes path and svc resolvers for infra servers.
//
// The connection factory is used to open sockets for SVC resolution requests.
// If the connection factory is nil, the default connection factory is used.
func (nc *NetworkConfig) AddressRewriter(
	connFactory snet.PacketDispatcherService) *messenger.AddressRewriter {

	router := nc.Router
	if router == nil {
		router = &snet.BaseRouter{Querier: snet.IntraASPathQuerier{IA: nc.IA}}
	}
	if connFactory == nil {
		connFactory = &snet.DefaultPacketDispatcherService{
			Dispatcher: reliable.NewDispatcher(""),
		}
	}

	return &messenger.AddressRewriter{
		Router:    router,
		SVCRouter: nc.SVCRouter,
		Resolver: &svc.Resolver{
			LocalIA:     nc.IA,
			ConnFactory: connFactory,
			LocalIP:     nc.Public.IP,
			// Legacy control payloads have a 4-byte length prefix. A
			// 0-value for the prefix is invalid, so SVC resolution-aware
			// servers can use this to detect that the client is attempting
			// SVC resolution. Legacy SVC traffic sent by legacy clients
			// will have a non-0 value, and thus not trigger resolution
			// logic.
			Payload: resolutionRequestPayload,
		},
		SVCResolutionFraction: nc.SVCResolutionFraction,
	}
}

// initUDPSocket creates the main control-plane UDP socket. SVC anycasts will
// be delivered to this socket, which can be configured to reply to SVC
// resolution requests. If argument address is not the empty string, it will be
// included as the QUIC address in SVC resolution replies.
func (nc *NetworkConfig) initUDPSocket(quicAddress string) (net.PacketConn, error) {
	reply := &svc.Reply{
		Transports: map[svc.Transport]string{
			svc.UDP: nc.Public.String(),
		},
	}

	if quicAddress != "" {
		reply.Transports[svc.QUIC] = quicAddress
	}

	udpAddressStr := &bytes.Buffer{}
	if err := reply.SerializeTo(udpAddressStr); err != nil {
		return nil, common.NewBasicError("Unable to build SVC resolution reply", err)
	}

	dispatcherService := reliable.NewDispatcher("")
	if nc.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}
	packetDispatcher := svc.NewResolverPacketDispatcher(
		&snet.DefaultPacketDispatcherService{
			Dispatcher: dispatcherService,
		},
		&LegacyForwardingHandler{
			BaseHandler: &svc.BaseHandler{
				Message: udpAddressStr.Bytes(),
			},
			ExpectedPayload: resolutionRequestPayload,
		},
	)
	network := snet.NewCustomNetworkWithPR(nc.IA, packetDispatcher)
	conn, err := network.Listen(context.Background(), "udp", nc.Public, nc.SVC)
	if err != nil {
		return nil, common.NewBasicError("Unable to listen on SCION", err)
	}
	return conn, nil
}

func (nc *NetworkConfig) initQUICSocket() (net.PacketConn, error) {
	dispatcherService := reliable.NewDispatcher("")
	if nc.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}

	network := snet.NewCustomNetworkWithPR(nc.IA,
		&snet.DefaultPacketDispatcherService{
			Dispatcher:  dispatcherService,
			SCMPHandler: ignoreSCMP{},
		},
	)
	udpAddr, err := net.ResolveUDPAddr("udp", nc.QUIC.Address)
	if err != nil {
		return nil, common.NewBasicError("Unable to parse address", err)
	}
	conn, err := network.Listen(context.Background(), "udp", udpAddr, addr.SvcNone)
	if err != nil {
		return nil, common.NewBasicError("Unable to listen on SCION", err)
	}
	return conn, nil
}

func (nc *NetworkConfig) buildQUICConfig(conn net.PacketConn) (*messenger.QUICConfig, error) {
	cert, err := tls.LoadX509KeyPair(nc.QUIC.CertFile, nc.QUIC.KeyFile)
	if err != nil {
		return nil, err
	}
	return &messenger.QUICConfig{
		Conn: conn,
		TLSConfig: &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
			NextProtos:         []string{"SCION"},
		},
	}, nil
}

// LegacyForwardingHandler is an SVC resolution handler that only responds to
// packets that have an SVC destination address and contain exactly 4 0x00
// bytes in their payload. All other packets are considered to originate from
// speakers that do not support SVC resolution, so they are forwarded to the
// application unchanged.
type LegacyForwardingHandler struct {
	ExpectedPayload []byte
	// BaseHandler is called after the payload is checked for the correct
	// content.
	BaseHandler *svc.BaseHandler
}

// Handle redirects packets that have an SVC destination address and contain
// exactly 4 0x00 bytes to another handler, and forwards other packets back to
// the application.
func (h *LegacyForwardingHandler) Handle(request *svc.Request) (svc.Result, error) {
	p, ok := request.Packet.Payload.(common.RawBytes)
	if !ok {
		return svc.Error, common.NewBasicError("Unsupported payload type", nil,
			"payload", request.Packet.Payload)
	}
	if bytes.Compare(h.ExpectedPayload, []byte(p)) == 0 {
		return h.BaseHandler.Handle(request)
	}
	log.Trace("Received control payload with SVC destination", "from", request.Packet.Source)
	return svc.Forward, nil
}

// NewRouter constructs a path router for paths starting from localIA.
func NewRouter(localIA addr.IA, sd env.SCIONDClient) (snet.Router, error) {
	ticker := time.NewTicker(time.Second)
	timer := time.NewTimer(sd.InitialConnectPeriod.Duration)
	ctx, cancelF := context.WithTimeout(context.Background(), sd.InitialConnectPeriod.Duration)
	defer cancelF()
	defer ticker.Stop()
	defer timer.Stop()
	// XXX(roosd): Initial retrying is implemented here temporarily.
	// In https://github.com/scionproto/scion/issues/1974 this will be
	// done transparently and pushed to snet.NewNetwork.
	var router snet.Router
	for {
		sciondConn, err := sciond.NewService(sd.Address).Connect(ctx)
		if err == nil {
			router = &snet.BaseRouter{
				Querier: sciond.Querier{
					Connector: sciondConn,
					IA:        localIA,
				},
			}
			break
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return nil, common.NewBasicError("Timed out during initial sciond connect", err)
		}
	}
	return router, nil
}

func InitInfraEnvironment(topologyPath string) {
	InitInfraEnvironmentFunc(topologyPath, nil)
}

// InitInfraEnvironmentFunc sets up the environment by first calling
// env.RealoadTopology and then the provided function.
func InitInfraEnvironmentFunc(topologyPath string, f func()) {
	env.SetupEnv(
		func() {
			env.ReloadTopology(topologyPath)
			if f != nil {
				f()
			}
		},
	)
}

// ignoreSCMP ignores all received SCMP packets.
//
// FIXME(scrye): Different services will want to process SCMP revocations in
// different ways, for example, to update their custom path stores (PS) or
// inform local SCION state (CS informing the local SD).
type ignoreSCMP struct{}

func (ignoreSCMP) Handle(pkt *snet.Packet) error {
	// Always reattempt reads from the socket.
	return nil
}
