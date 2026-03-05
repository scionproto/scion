// Copyright 2026 ETH Zurich
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

package main

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	cs "github.com/scionproto/scion/control"
	hbirdconnect "github.com/scionproto/scion/hbird/hbserver/connect"
	hbirdgrpc "github.com/scionproto/scion/hbird/hbserver/grpc"
	libconnect "github.com/scionproto/scion/pkg/connect"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
	infraenv "github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/trust"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	//libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"

	//"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app"
	//infraenv "github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/topology"
	//"github.com/scionproto/scion/private/trust"

	"github.com/scionproto/scion/private/app/launcher"
	"github.com/scionproto/scion/private/keyconf"

	hb "github.com/scionproto/scion/hbird"
	"github.com/scionproto/scion/hbird/config"

	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	hbirdv1connect "github.com/scionproto/scion/pkg/proto/hbird/v1/hbirdconnect"
)

var globalCfg config.Config

const (
	// Server constants
	serverPort     = 30258
	defaultTrustDB = "/run/cs-1.trust.db"
)

func loadHBMasterSecret(path string) (masterKey [16]byte) {
	masterKeys, err := keyconf.LoadMaster(path)
	// We load both master keys, but only use key0
	if err != nil || len(masterKeys.Key0) != 16 {
		panic(err)
	}
	copy(masterKey[:], masterKeys.Key0[0:16])
	return
}

func trustDBPath() string {
	if globalCfg.HB.TrustDBPath != "" {
		return globalCfg.HB.TrustDBPath
	}
	return defaultTrustDB
}

func main() {
	application := launcher.Application{
		ApplicationBase: launcher.ApplicationBase{
			TOMLConfig: &globalCfg,
			ShortName:  "SCION Hummingbird Service",
			Main:       realMain,
		},
	}
	application.Run()
}

func realMain(ctx context.Context) error {
	metrics := hb.NewMetrics()

	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:   globalCfg.General.Topology(),
		Reload: app.SIGHUPChannel(ctx),
		//Validator: &topology.HbirdValidator{ID: globalCfg.General.ID},
		Metrics: metrics.TopoLoader,
	})
	if err != nil {
		return serrors.Wrap("creating topology loader", err)
	}
	g, errCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer log.HandlePanic()
		return topo.Run(errCtx)
	})

	trustDB, err := storage.NewTrustStorage(storage.DBConfig{Connection: trustDBPath()})
	if err != nil {
		return serrors.Wrap("initializing trust storage", err)
	}
	defer trustDB.Close()
	nc := infraenv.NetworkConfig{
		IA:     topo.IA(),
		Public: &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: serverPort},
		QUIC: infraenv.QUIC{
			TLSVerifier: trust.NewTLSCryptoVerifier(trustDB),
			GetCertificate: cs.NewTLSCertificateLoader(
				topo.IA(), x509.ExtKeyUsageServerAuth, trustDB, globalCfg.General.ConfigDir,
			).GetCertificate,
			GetClientCertificate: cs.NewTLSCertificateLoader(
				topo.IA(), x509.ExtKeyUsageClientAuth, trustDB, globalCfg.General.ConfigDir,
			).GetClientCertificate,
		},
		SVCResolver:            topo,
		SCMPHandler:            snet.DefaultSCMPHandler{},
		SCIONNetworkMetrics:    snet.SCIONNetworkMetrics{},
		SCIONPacketConnMetrics: snet.SCIONPacketConnMetrics{},
		MTU:                    topo.MTU(),
		Topology: func(topo *topology.Loader) snet.Topology {
			start, end := topo.PortRange()
			return snet.Topology{
				LocalIA: topo.IA(),
				PortRange: snet.TopologyPortRange{
					Start: start,
					End:   end,
				},
				Interface: func(ifID uint16) (netip.AddrPort, bool) {
					a := topo.UnderlayNextHop(ifID)
					if a == nil {
						return netip.AddrPort{}, false
					}
					return a.AddrPort(), true
				},
			}
		}(topo),
	}

	quicStack, err := nc.QUICStack(ctx)
	if err != nil {
		return serrors.Wrap("initializing QUIC stack", err)
	}

	quicServer := grpc.NewServer(
		grpc.Creds(libgrpc.PassThroughCredentials{}),
		libgrpc.UnaryServerInterceptor(),
		libgrpc.DefaultMaxConcurrentStreams(),
	)
	// distinguish between inter and intra AS request origin
	connectInter := http.NewServeMux()
	connectIntra := http.NewServeMux()

	masterKey := loadHBMasterSecret(filepath.Join(globalCfg.General.ConfigDir, "dummy_keys"))

	// Create the service
	svc := hbirdconnect.NewHummingbirdKeyDerivationService(masterKey)
	icm := hb.NewIntervalColorMap(10)
	hbs := &hbirdgrpc.HBirdServer{Topo: topo, HbService: svc, Icm: icm}
	connectSrv := &hbirdconnect.HBirdServer{Topo: topo, HbService: svc, Icm: icm}

	hbirdv1.RegisterHBirdServiceServer(quicServer, hbs)
	connectInter.Handle(
		hbirdv1connect.NewHBirdServiceHandler(
			connectSrv,
			connect.WithInterceptors(validate.NewInterceptor()),
		),
	)
	connectIntra.Handle(
		hbirdv1connect.NewHBirdServiceHandler(
			connectSrv,
			connect.WithInterceptors(validate.NewInterceptor()),
		),
	)

	var cleanup app.Cleanup
	connectServer := http3.Server{
		Handler: libconnect.AttachPeer(connectInter),
	}

	grpcConns := make(chan *quic.Conn)
	g.Go(func() error {
		defer log.HandlePanic()
		listener := quicStack.Listener
		for {
			conn, err := listener.Accept(context.Background())
			if err == quic.ErrServerClosed {
				return http.ErrServerClosed
			}
			if err != nil {
				return err
			}
			go func() {
				defer log.HandlePanic()
				if conn.ConnectionState().TLS.NegotiatedProtocol != "h3" {
					log.Debug("NegotiatedProtocol not h3, switching to grpc",
						"proto", conn.ConnectionState().TLS.NegotiatedProtocol)
					grpcConns <- conn
					return
				}

				if err := connectServer.ServeQUICConn(conn); err != nil {
					log.Debug("Error handling connectrpc connection", "err", err)
				}
			}()
		}
	})

	g.Go(func() error {
		defer log.HandlePanic()
		grpcListener := squic.NewConnListener(grpcConns, quicStack.Listener.Addr())
		if err := quicServer.Serve(grpcListener); err != nil {
			return serrors.Wrap("serving gRPC/SCION API", err)
		}
		return nil
	})
	cleanup.Add(func() error { quicServer.GracefulStop(); return nil })

	intraServer := http.Server{
		Handler: h2c.NewHandler(libconnect.AttachPeer(connectIntra), &http2.Server{}),
	}

	g.Go(func() error {
		defer log.HandlePanic()
		tcpListener, err := nc.TCPStack()
		if err != nil {
			return serrors.Wrap("initializing TCP stack", err)
		}
		if err := intraServer.Serve(tcpListener); err != nil {
			return serrors.Wrap("serving connect/TCP API", err)
		}
		return nil
	})

	cleanup.Add(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if err := intraServer.Shutdown(ctx); err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	})

	g.Go(func() error {
		defer log.HandlePanic()
		<-errCtx.Done()
		return cleanup.Do()
	})

	return g.Wait()
}
