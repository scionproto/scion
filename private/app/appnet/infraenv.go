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
package appnet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/pkg/sock/reliable"
	"github.com/scionproto/scion/pkg/sock/reliable/reconnect"
	"github.com/scionproto/scion/private/env"
	"github.com/scionproto/scion/private/svc"
)

// QUIC contains the QUIC configuration for control-plane speakers.
type QUIC struct {
	// Address is the UDP address to start the QUIC server on.
	Address string
}

// NetworkConfig describes the networking configuration of a SCION
// control-plane RPC endpoint.
type NetworkConfig struct {
	// IA is the local AS number.
	IA addr.IA
	// Public is the Internet-reachable address in the case where the service
	// is behind NAT.
	Public *net.UDPAddr
	// ReconnectToDispatcher sets up sockets that automatically reconnect if
	// the dispatcher closes the connection (e.g., if the dispatcher goes
	// down).
	ReconnectToDispatcher bool
	// QUIC contains configuration details for QUIC servers. If the listening
	// address is the empty string, then no QUIC socket is opened.
	QUIC QUIC
	// SVCResolver is used to discover the underlay addresses of intra-AS SVC
	// servers.
	SVCResolver SVCResolver
	// SCMPHandler is the SCMP handler to use. This handler is only applied to
	// client connections. The connection the server listens on will always
	// ignore SCMP messages. Otherwise, the server will shutdown when receiving
	// an SCMP error message.
	SCMPHandler snet.SCMPHandler
	// Metrics injected into SCIONNetwork.
	SCIONNetworkMetrics snet.SCIONNetworkMetrics
	// Metrics injected into DefaultPacketDispatcherService.
	SCIONPacketConnMetrics snet.SCIONPacketConnMetrics
}

// QUICStack contains everything to run a QUIC based RPC stack.
type QUICStack struct {
	Listener       *squic.ConnListener
	Dialer         *squic.ConnDialer
	RedirectCloser func()
}

func (nc *NetworkConfig) TCPStack() (net.Listener, error) {
	return net.ListenTCP("tcp", &net.TCPAddr{
		IP:   nc.Public.IP,
		Port: nc.Public.Port,
		Zone: nc.Public.Zone,
	})
}

func (nc *NetworkConfig) QUICStack() (*QUICStack, error) {
	if nc.QUIC.Address == "" {
		nc.QUIC.Address = net.JoinHostPort(nc.Public.IP.String(), "0")
	}
	client, server, err := nc.initQUICSockets()
	if err != nil {
		return nil, err
	}
	log.Info("QUIC server conn initialized", "local_addr", server.LocalAddr())
	log.Info("QUIC client conn initialized", "local_addr", client.LocalAddr())

	tlsConfig, err := GenerateTLSConfig()
	if err != nil {
		return nil, err
	}
	listener, err := quic.Listen(server, tlsConfig, nil)
	if err != nil {
		return nil, serrors.WrapStr("listening QUIC/SCION", err)
	}

	serverAddr, ok := server.LocalAddr().(*snet.UDPAddr)
	if !ok {
		return nil, serrors.New("unexpected server address type",
			"type", fmt.Sprintf("%T", server.LocalAddr()),
		)
	}

	cancel, err := nc.initSvcRedirect(serverAddr.Host.String())
	if err != nil {
		return nil, serrors.WrapStr("starting service redirection", err)
	}

	return &QUICStack{
		Listener: squic.NewConnListener(listener),
		Dialer: &squic.ConnDialer{
			Conn:      client,
			TLSConfig: tlsConfig,
		},
		RedirectCloser: cancel,
	}, nil
}

// GenerateTLSConfig generates a self-signed certificate.
func GenerateTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, serrors.WrapStr("creating random serial number", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "scion_def_srv",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
		NextProtos:         []string{"SCION"},
	}, nil
}

// AddressRewriter initializes path and svc resolvers for infra servers.
//
// The connection factory is used to open sockets for SVC resolution requests.
// If the connection factory is nil, the default connection factory is used.
func (nc *NetworkConfig) AddressRewriter(
	connFactory snet.PacketDispatcherService) *AddressRewriter {

	if connFactory == nil {
		connFactory = &snet.DefaultPacketDispatcherService{
			Dispatcher:  reliable.NewDispatcher(""),
			SCMPHandler: nc.SCMPHandler,
		}
	}
	return &AddressRewriter{
		Router:    &snet.BaseRouter{Querier: snet.IntraASPathQuerier{IA: nc.IA}},
		SVCRouter: nc.SVCResolver,
		Resolver: &svc.Resolver{
			LocalIA:     nc.IA,
			ConnFactory: connFactory,
			LocalIP:     nc.Public.IP,
		},
		SVCResolutionFraction: 1.337,
	}
}

// initSvcRedirect creates the main control-plane UDP socket. SVC anycasts will be
// delivered to this socket, which replies to SVC resolution requests. The
// address will be included as the QUIC address in SVC resolution replies.
func (nc *NetworkConfig) initSvcRedirect(quicAddress string) (func(), error) {
	reply := &svc.Reply{
		Transports: map[svc.Transport]string{
			svc.QUIC: quicAddress,
		},
	}

	svcResolutionReply, err := reply.Marshal()
	if err != nil {
		return nil, serrors.WrapStr("building SVC resolution reply", err)
	}

	dispatcherService := reliable.NewDispatcher("")
	if nc.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}
	packetDispatcher := svc.NewResolverPacketDispatcher(
		&snet.DefaultPacketDispatcherService{
			Dispatcher:             dispatcherService,
			SCMPHandler:            nc.SCMPHandler,
			SCIONPacketConnMetrics: nc.SCIONPacketConnMetrics,
		},
		&svc.BaseHandler{
			Message: svcResolutionReply,
		},
	)
	network := &snet.SCIONNetwork{
		LocalIA:    nc.IA,
		Dispatcher: packetDispatcher,
		Metrics:    nc.SCIONNetworkMetrics,
	}
	conn, err := network.Listen(context.Background(), "udp", nc.Public, addr.SvcWildcard)
	if err != nil {
		return nil, serrors.WrapStr("listening on SCION", err, "addr", nc.Public)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer log.HandlePanic()
		buf := make([]byte, 1500)
		done := ctx.Done()
		for {
			select {
			case <-done:
				return
			default:
				conn.Read(buf)
			}
		}
	}()
	return cancel, nil
}

func (nc *NetworkConfig) initQUICSockets() (net.PacketConn, net.PacketConn, error) {
	dispatcherService := reliable.NewDispatcher("")
	if nc.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}

	serverNet := &snet.SCIONNetwork{
		LocalIA: nc.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher: dispatcherService,
			// XXX(roosd): This is essential, the server must not read SCMP
			// errors. Otherwise, the accept loop will always return that error
			// on every subsequent call to accept.
			SCMPHandler:            ignoreSCMP{},
			SCIONPacketConnMetrics: nc.SCIONPacketConnMetrics,
		},
		Metrics: nc.SCIONNetworkMetrics,
	}
	serverAddr, err := net.ResolveUDPAddr("udp", nc.QUIC.Address)
	if err != nil {
		return nil, nil, serrors.WrapStr("parsing server QUIC address", err)
	}
	server, err := serverNet.Listen(context.Background(), "udp", serverAddr, addr.SvcNone)
	if err != nil {
		return nil, nil, serrors.WrapStr("creating server connection", err)
	}

	clientNet := &snet.SCIONNetwork{
		LocalIA: nc.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher:             dispatcherService,
			SCMPHandler:            nc.SCMPHandler,
			SCIONPacketConnMetrics: nc.SCIONPacketConnMetrics,
		},
		Metrics: nc.SCIONNetworkMetrics,
	}
	// Let the dispatcher decide on the port for the client connection.
	clientAddr := &net.UDPAddr{
		IP:   serverAddr.IP,
		Zone: serverAddr.Zone,
	}
	client, err := clientNet.Listen(context.Background(), "udp", clientAddr, addr.SvcNone)
	if err != nil {
		return nil, nil, serrors.WrapStr("creating client connection", err)
	}
	return client, server, nil
}

// NewRouter constructs a path router for paths starting from localIA.
func NewRouter(localIA addr.IA, sd env.Daemon) (snet.Router, error) {
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
		daemonConn, err := daemon.NewService(sd.Address).Connect(ctx)
		if err == nil {
			router = &snet.BaseRouter{
				Querier: daemon.Querier{
					Connector: daemonConn,
					IA:        localIA,
				},
			}
			break
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return nil, serrors.WrapStr("Timed out during initial daemon connect", err)
		}
	}
	return router, nil
}

// ignoreSCMP ignores all received SCMP packets.
//
// XXX(roosd): This is needed such that the QUIC server does not shut down when
// receiving a SCMP error. DO NOT REMOVE!
type ignoreSCMP struct{}

func (ignoreSCMP) Handle(pkt *snet.Packet) error {
	// Always reattempt reads from the socket.
	return nil
}
