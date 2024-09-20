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
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/env"
	"github.com/scionproto/scion/private/svc"
	"github.com/scionproto/scion/private/trust"
)

// QUIC contains the QUIC configuration for control-plane speakers.
type QUIC struct {
	GetCertificate       func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	TLSVerifier          *trust.TLSCryptoVerifier
}

// NetworkConfig describes the networking configuration of a SCION
// control-plane RPC endpoint.
type NetworkConfig struct {
	// IA is the local AS number.
	IA addr.IA
	// Public is the Internet-reachable address in the case where the service
	// is behind NAT.
	Public *net.UDPAddr
	// QUIC contains configuration details for QUIC servers.
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
	// Metrics injected into SCIONPacketConn.
	SCIONPacketConnMetrics snet.SCIONPacketConnMetrics
	// MTU of the local AS
	MTU uint16
	// Topology is the helper class to get control-plane information for the
	// local AS.
	Topology snet.Topology
}

// QUICStack contains everything to run a QUIC based RPC stack.
type QUICStack struct {
	Listener       *squic.ConnListener
	InsecureDialer *squic.ConnDialer
	Dialer         *squic.ConnDialer
}

func (nc *NetworkConfig) TCPStack() (net.Listener, error) {
	return net.ListenTCP("tcp", &net.TCPAddr{
		IP:   nc.Public.IP,
		Port: nc.Public.Port,
		Zone: nc.Public.Zone,
	})
}

func (nc *NetworkConfig) QUICStack() (*QUICStack, error) {

	client, server, err := nc.initQUICSockets()
	if err != nil {
		return nil, err
	}
	log.Info("QUIC server conn initialized", "local_addr", server.LocalAddr())
	log.Info("QUIC client conn initialized", "local_addr", client.LocalAddr())

	serverTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		GetCertificate:     nc.QUIC.GetCertificate,
		ClientAuth:         tls.RequestClientCert,
		NextProtos:         []string{"SCION"},
	}

	listener, err := quic.Listen(server, serverTLSConfig, nil)
	if err != nil {
		return nil, serrors.Wrap("listening QUIC/SCION", err)
	}

	insecureClientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"SCION"},
	}
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify:    true, // ... but VerifyServerCertificate and VerifyConnection
		GetClientCertificate:  nc.QUIC.GetClientCertificate,
		VerifyPeerCertificate: nc.QUIC.TLSVerifier.VerifyServerCertificate,
		VerifyConnection:      nc.QUIC.TLSVerifier.VerifyConnection,
		NextProtos:            []string{"SCION"},
	}
	clientTransport := &quic.Transport{
		Conn: client,
	}

	return &QUICStack{
		Listener: squic.NewConnListener(listener),
		InsecureDialer: &squic.ConnDialer{
			Transport: clientTransport,
			TLSConfig: insecureClientTLSConfig,
		},
		Dialer: &squic.ConnDialer{
			Transport: clientTransport,
			TLSConfig: clientTLSConfig,
		},
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
		return nil, serrors.Wrap("creating random serial number", err)
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
// The connector is used to open sockets for SVC resolution requests.
// If the connector is nil, the default connection factory is used.
func (nc *NetworkConfig) AddressRewriter() *AddressRewriter {
	return &AddressRewriter{
		Router:    &snet.BaseRouter{Querier: IntraASPathQuerier{IA: nc.IA, MTU: nc.MTU}},
		SVCRouter: nc.SVCResolver,
		Resolver: &svc.Resolver{
			LocalIA: nc.IA,
			Network: &snet.SCIONNetwork{
				Topology:          nc.Topology,
				SCMPHandler:       nc.SCMPHandler,
				Metrics:           nc.SCIONNetworkMetrics,
				PacketConnMetrics: nc.SCIONPacketConnMetrics,
			},
			LocalIP: nc.Public.IP,
		},
	}
}

func (nc *NetworkConfig) initQUICSockets() (net.PacketConn, net.PacketConn, error) {
	reply := &svc.Reply{
		Transports: map[svc.Transport]string{
			svc.QUIC: nc.Public.String(),
		},
	}

	svcResolutionReply, err := reply.Marshal()
	if err != nil {
		return nil, nil, serrors.Wrap("building SVC resolution reply", err)
	}

	serverNet := &snet.SCIONNetwork{
		Topology: nc.Topology,
		// XXX(roosd): This is essential, the server must not read SCMP
		// errors. Otherwise, the accept loop will always return that error
		// on every subsequent call to accept.
		SCMPHandler:       ignoreSCMP{},
		PacketConnMetrics: nc.SCIONPacketConnMetrics,
	}
	pconn, err := serverNet.OpenRaw(context.Background(), nc.Public)
	if err != nil {
		return nil, nil, serrors.Wrap("creating server raw PacketConn", err)
	}
	resolvedPacketConn := &svc.ResolverPacketConn{
		PacketConn: pconn,
		Source: snet.SCIONAddress{
			IA:   nc.IA,
			Host: addr.HostIP(nc.Public.AddrPort().Addr()),
		},
		Handler: &svc.BaseHandler{
			Message: svcResolutionReply,
		},
	}
	server, err := snet.NewCookedConn(resolvedPacketConn, nc.Topology)
	if err != nil {
		return nil, nil, serrors.Wrap("creating server connection", err)
	}

	clientNet := &snet.SCIONNetwork{
		Topology: nc.Topology,
		// Discard all SCMP propagation, to avoid read errors on the QUIC
		// client.
		SCMPHandler: snet.SCMPPropagationStopper{
			Handler: nc.SCMPHandler,
			Log:     log.Debug,
		},
		Metrics:           nc.SCIONNetworkMetrics,
		PacketConnMetrics: nc.SCIONPacketConnMetrics,
	}
	clientAddr := &net.UDPAddr{
		IP:   nc.Public.IP,
		Zone: nc.Public.Zone,
	}
	client, err := clientNet.Listen(context.Background(), "udp", clientAddr)
	if err != nil {
		return nil, nil, serrors.Wrap("creating client connection", err)
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
			return nil, serrors.Wrap("Timed out during initial daemon connect", err)
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
