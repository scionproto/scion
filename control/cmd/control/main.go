// Copyright 2020 Anapaya Systems
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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	promgrpc "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	cs "github.com/scionproto/scion/control"
	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	beaconingconnect "github.com/scionproto/scion/control/beaconing/connect"
	beaconinggrpc "github.com/scionproto/scion/control/beaconing/grpc"
	"github.com/scionproto/scion/control/beaconing/happy"
	"github.com/scionproto/scion/control/config"
	"github.com/scionproto/scion/control/drkey"
	drkeyconnect "github.com/scionproto/scion/control/drkey/connect"
	drkeygrpc "github.com/scionproto/scion/control/drkey/grpc"
	drkeyhappy "github.com/scionproto/scion/control/drkey/happy"
	"github.com/scionproto/scion/control/ifstate"
	api "github.com/scionproto/scion/control/mgmtapi"
	"github.com/scionproto/scion/control/onehop"
	"github.com/scionproto/scion/control/segreg"
	segregconnect "github.com/scionproto/scion/control/segreg/connect"
	segreggrpc "github.com/scionproto/scion/control/segreg/grpc"
	"github.com/scionproto/scion/control/segreq"
	segreqconnect "github.com/scionproto/scion/control/segreq/connect"
	segreqgrpc "github.com/scionproto/scion/control/segreq/grpc"
	cstrust "github.com/scionproto/scion/control/trust"
	cstrustconnect "github.com/scionproto/scion/control/trust/connect"
	cstrustgrpc "github.com/scionproto/scion/control/trust/grpc"
	cstrustmetrics "github.com/scionproto/scion/control/trust/metrics"
	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	libmetrics "github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	cpconnect "github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	dpb "github.com/scionproto/scion/pkg/proto/discovery"
	dconnect "github.com/scionproto/scion/pkg/proto/discovery/v1/discoveryconnect"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	discoveryext "github.com/scionproto/scion/pkg/segment/extensions/discovery"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/app"
	infraenv "github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/app/launcher"
	caapi "github.com/scionproto/scion/private/ca/api"
	caconfig "github.com/scionproto/scion/private/ca/config"
	"github.com/scionproto/scion/private/ca/renewal"
	renewalconnect "github.com/scionproto/scion/private/ca/renewal/connect"
	renewalgrpc "github.com/scionproto/scion/private/ca/renewal/grpc"
	"github.com/scionproto/scion/private/discovery"
	discoveryconnect "github.com/scionproto/scion/private/discovery/connect"
	"github.com/scionproto/scion/private/drkey/drkeyutil"
	"github.com/scionproto/scion/private/keyconf"
	cppkiapi "github.com/scionproto/scion/private/mgmtapi/cppki/api"
	"github.com/scionproto/scion/private/mgmtapi/jwtauth"
	segapi "github.com/scionproto/scion/private/mgmtapi/segments/api"
	"github.com/scionproto/scion/private/periodic"
	segfetcherconnect "github.com/scionproto/scion/private/segment/segfetcher/connect"
	segfetchergrpc "github.com/scionproto/scion/private/segment/segfetcher/grpc"
	segfetcherhappy "github.com/scionproto/scion/private/segment/segfetcher/happy"
	"github.com/scionproto/scion/private/segment/seghandler"
	"github.com/scionproto/scion/private/service"
	"github.com/scionproto/scion/private/storage"
	beaconstoragemetrics "github.com/scionproto/scion/private/storage/beacon/metrics"
	"github.com/scionproto/scion/private/storage/drkey/level1"
	"github.com/scionproto/scion/private/storage/drkey/secret"
	pathstoragemetrics "github.com/scionproto/scion/private/storage/path/metrics"
	truststoragefspersister "github.com/scionproto/scion/private/storage/trust/fspersister"
	truststoragemetrics "github.com/scionproto/scion/private/storage/trust/metrics"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/compat"
	trustconnect "github.com/scionproto/scion/private/trust/connect"
	trustgrpc "github.com/scionproto/scion/private/trust/grpc"
	trusthappy "github.com/scionproto/scion/private/trust/happy"
	trustmetrics "github.com/scionproto/scion/private/trust/metrics"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		ApplicationBase: launcher.ApplicationBase{
			TOMLConfig: &globalCfg,
			ShortName:  "SCION Control Service",
			// TODO(scrye): Deprecated additional sampler, remove once Anapaya/scion#5000 is in.
			Samplers: []func(command.Pather) *cobra.Command{newSamplePolicy},
			Main:     realMain,
		},
	}
	application.Run()
}

func realMain(ctx context.Context) error {
	metrics := cs.NewMetrics()

	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:      globalCfg.General.Topology(),
		Reload:    app.SIGHUPChannel(ctx),
		Validator: &topology.ControlValidator{ID: globalCfg.General.ID},
		Metrics:   metrics.TopoLoader,
	})
	if err != nil {
		return serrors.Wrap("creating topology loader", err)
	}
	g, errCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer log.HandlePanic()
		return topo.Run(errCtx)
	})
	intfs := ifstate.NewInterfaces(adaptInterfaceMap(topo.InterfaceInfoMap()), ifstate.Config{})
	g.Go(func() error {
		defer log.HandlePanic()
		sub := topo.Subscribe()
		defer sub.Close()
		for {
			select {
			case <-sub.Updates:
				intfs.Update(adaptInterfaceMap(topo.InterfaceInfoMap()))
			case <-errCtx.Done():
				return nil
			}
		}
	})

	closer, err := cs.InitTracer(globalCfg.Tracing, globalCfg.General.ID)
	if err != nil {
		return serrors.Wrap("initializing tracer", err)
	}
	defer closer.Close()

	revCache := storage.NewRevocationStorage()
	defer revCache.Close()
	pathDB, err := storage.NewPathStorage(globalCfg.PathDB)
	if err != nil {
		return serrors.Wrap("initializing path storage", err)
	}
	pathDB = pathstoragemetrics.WrapDB(pathDB, pathstoragemetrics.Config{
		Driver:       string(storage.BackendSqlite),
		QueriesTotal: libmetrics.NewPromCounter(metrics.PathDBQueriesTotal),
	})
	defer pathDB.Close()

	macGen, err := cs.MACGenFactory(globalCfg.General.ConfigDir)
	if err != nil {
		return err
	}

	trustDB, err := storage.NewTrustStorage(globalCfg.TrustDB)
	if err != nil {
		return serrors.Wrap("initializing trust storage", err)
	}
	defer trustDB.Close()
	fileWrites := libmetrics.NewPromCounter(metrics.TrustTRCFileWritesTotal)
	trustDB = truststoragefspersister.WrapDB(
		trustDB,
		truststoragefspersister.Config{
			TRCDir: filepath.Join(globalCfg.General.ConfigDir, "certs"),
			Metrics: truststoragefspersister.Metrics{
				TRCFileWriteSuccesses: fileWrites.With(
					prom.LabelResult,
					truststoragefspersister.WriteSuccess,
				),
				TRCFileWriteErrors: fileWrites.With(
					prom.LabelResult,
					truststoragefspersister.WriteError,
				),
				TRCFileStatErrors: fileWrites.With(
					prom.LabelResult,
					truststoragefspersister.StatError,
				),
			},
		},
	)
	trustDB = truststoragemetrics.WrapDB(trustDB, truststoragemetrics.Config{
		Driver:       string(storage.BackendSqlite),
		QueriesTotal: libmetrics.NewPromCounter(metrics.TrustDBQueriesTotal),
	})
	if err := cs.LoadTrustMaterial(ctx, globalCfg.General.ConfigDir, trustDB); err != nil {
		return err
	}

	// FIXME: readability would be improved if we could be consistent with address
	// representations in NetworkConfig (string or cooked, chose one).
	nc := infraenv.NetworkConfig{
		IA:     topo.IA(),
		Public: topo.ControlServiceAddress(globalCfg.General.ID),
		QUIC: infraenv.QUIC{
			TLSVerifier: trust.NewTLSCryptoVerifier(trustDB),
			GetCertificate: cs.NewTLSCertificateLoader(
				topo.IA(), x509.ExtKeyUsageServerAuth, trustDB, globalCfg.General.ConfigDir,
			).GetCertificate,
			GetClientCertificate: cs.NewTLSCertificateLoader(
				topo.IA(), x509.ExtKeyUsageClientAuth, trustDB, globalCfg.General.ConfigDir,
			).GetClientCertificate,
		},
		SVCResolver: topo,
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: cs.RevocationHandler{RevCache: revCache},
			SCMPErrors:        metrics.SCMPErrors,
		},
		SCIONNetworkMetrics:    metrics.SCIONNetworkMetrics,
		SCIONPacketConnMetrics: metrics.SCIONPacketConnMetrics,
		MTU:                    topo.MTU(),
		Topology:               adaptTopology(topo),
	}
	quicStack, err := nc.QUICStack(ctx)
	if err != nil {
		return serrors.Wrap("initializing QUIC stack", err)
	}
	dialer := &libgrpc.QUICDialer{
		Rewriter: &onehop.AddressRewriter{
			Rewriter: nc.AddressRewriter(),
			MAC:      macGen(),
		},
		Dialer: quicStack.InsecureDialer,
	}

	beaconDB, err := storage.NewBeaconStorage(globalCfg.BeaconDB, topo.IA())
	if err != nil {
		return serrors.Wrap("initializing beacon storage", err)
	}
	defer beaconDB.Close()
	beaconDB = beaconstoragemetrics.WrapDB(beaconDB, beaconstoragemetrics.Config{
		Driver:       string(storage.BackendSqlite),
		QueriesTotal: libmetrics.NewPromCounter(metrics.BeaconDBQueriesTotal),
	})

	policies, err := loadPolicies(topo.Core(), globalCfg.BS.Policies)
	if err != nil {
		return serrors.Wrap("loading policies", err)
	}
	beaconStore, isdLoopAllowed, err := createBeaconStore(
		policies,
		beaconDB,
		trust.FetchingProvider{
			DB:       trustDB,
			Recurser: trust.NeverRecurser{},
			// XXX(roosd): Do not set fetcher or router because they are not
			// used and we rather panic if they are reached due to a implementation
			// bug.
		},
	)
	if err != nil {
		return serrors.Wrap("initializing beacon store", err)
	}

	trustengineCache := globalCfg.TrustEngine.Cache.New()
	cacheHits := libmetrics.NewPromCounter(trustmetrics.CacheHitsTotal)
	inspector := trust.CachingInspector{
		Inspector: trust.DBInspector{
			DB: trustDB,
		},
		CacheHits:          cacheHits,
		MaxCacheExpiration: globalCfg.TrustEngine.Cache.Expiration.Duration,
		Cache:              trustengineCache,
	}
	provider := trust.FetchingProvider{
		DB: trustDB,
		Fetcher: trusthappy.Fetcher{
			Connect: trustconnect.Fetcher{
				IA: topo.IA(),
				Dialer: (&squic.EarlyDialerFactory{
					Transport: quicStack.InsecureDialer.Transport,
					TLSConfig: libconnect.AdaptClientTLS(quicStack.InsecureDialer.TLSConfig),
					Rewriter:  dialer.Rewriter,
				}).NewDialer,
			},
			Grpc: trustgrpc.Fetcher{
				IA:       topo.IA(),
				Dialer:   dialer,
				Requests: libmetrics.NewPromCounter(trustmetrics.RPC.Fetches),
			},
		},
		Recurser: trust.ASLocalRecurser{IA: topo.IA()},
		// XXX(roosd): cyclic dependency on router. It is set below.
	}
	verifier := compat.Verifier{
		Verifier: trust.Verifier{
			Engine:             provider,
			CacheHits:          cacheHits,
			MaxCacheExpiration: globalCfg.TrustEngine.Cache.Expiration.Duration,
			Cache:              trustengineCache,
		},
	}
	fetcherCfg := segreq.FetcherConfig{
		IA:            topo.IA(),
		MTU:           topo.MTU(),
		Core:          topo.Core(),
		NextHopper:    topo,
		PathDB:        pathDB,
		RevCache:      revCache,
		QueryInterval: globalCfg.PS.QueryInterval.Duration,
		RPC: &segfetcherhappy.Requester{
			Connect: &segfetcherconnect.Requester{
				Dialer: (&squic.EarlyDialerFactory{
					Transport: quicStack.InsecureDialer.Transport,
					TLSConfig: libconnect.AdaptClientTLS(quicStack.InsecureDialer.TLSConfig),
					Rewriter:  dialer.Rewriter,
				}).NewDialer,
			},
			Grpc: &segfetchergrpc.Requester{
				Dialer: dialer,
			},
		},
		Inspector: inspector,
		Verifier:  verifier,
	}
	provider.Router = trust.AuthRouter{
		ISD:    topo.IA().ISD(),
		DB:     trustDB,
		Router: segreq.NewRouter(fetcherCfg),
	}

	quicServer := grpc.NewServer(
		grpc.Creds(libgrpc.PassThroughCredentials{}),
		libgrpc.UnaryServerInterceptor(),
		libgrpc.DefaultMaxConcurrentStreams(),
	)
	connectInter := http.NewServeMux()
	connectIntra := http.NewServeMux()

	// Register trust material related handlers.
	trustServer := &cstrustgrpc.MaterialServer{
		Provider: provider,
		IA:       topo.IA(),
		Requests: libmetrics.NewPromCounter(cstrustmetrics.Handler.Requests),
	}
	cppb.RegisterTrustMaterialServiceServer(quicServer, trustServer)
	connectInter.Handle(cpconnect.NewTrustMaterialServiceHandler(cstrustconnect.MaterialServer{
		MaterialServer: trustServer,
	}))
	connectIntra.Handle(cpconnect.NewTrustMaterialServiceHandler(cstrustconnect.MaterialServer{
		MaterialServer: trustServer,
	}))

	// Handle beaconing.
	segmentCreationServer := &beaconinggrpc.SegmentCreationServer{
		Handler: &beaconing.Handler{
			LocalIA:        topo.IA(),
			Inserter:       beaconStore,
			Interfaces:     intfs,
			Verifier:       verifier,
			BeaconsHandled: libmetrics.NewPromCounter(metrics.BeaconingReceivedTotal),
		},
	}
	cppb.RegisterSegmentCreationServiceServer(quicServer, segmentCreationServer)
	connectInter.Handle(
		cpconnect.NewSegmentCreationServiceHandler(beaconingconnect.SegmentCreationServer{
			SegmentCreationServer: segmentCreationServer,
		}),
	)

	// Handle segment lookup
	authLookupServer := &segreqgrpc.LookupServer{
		Lookuper: segreq.AuthoritativeLookup{
			LocalIA:     topo.IA(),
			CoreChecker: segreq.CoreChecker{Inspector: inspector},
			PathDB:      pathDB,
		},
		RevCache:     revCache,
		Requests:     libmetrics.NewPromCounter(metrics.SegmentLookupRequestsTotal),
		SegmentsSent: libmetrics.NewPromCounter(metrics.SegmentLookupSegmentsSentTotal),
	}
	forwardingLookupServer := &segreqgrpc.LookupServer{
		Lookuper: segreq.ForwardingLookup{
			LocalIA:     topo.IA(),
			CoreChecker: segreq.CoreChecker{Inspector: inspector},
			Fetcher:     segreq.NewFetcher(fetcherCfg),
			Expander: segreq.WildcardExpander{
				LocalIA:   topo.IA(),
				Core:      topo.Core(),
				Inspector: inspector,
				PathDB:    pathDB,
			},
		},
		RevCache:     revCache,
		Requests:     libmetrics.NewPromCounter(metrics.SegmentLookupRequestsTotal),
		SegmentsSent: libmetrics.NewPromCounter(metrics.SegmentLookupSegmentsSentTotal),
	}

	// Always register a forwarding lookup for AS internal requests.
	connectIntra.Handle(cpconnect.NewSegmentLookupServiceHandler(segreqconnect.LookupServer{
		LookupServer: forwardingLookupServer,
	}))
	if topo.Core() {
		cppb.RegisterSegmentLookupServiceServer(quicServer, authLookupServer)
		connectInter.Handle(cpconnect.NewSegmentLookupServiceHandler(segreqconnect.LookupServer{
			LookupServer: authLookupServer,
		}))
	}

	// Handle segment registration.
	if topo.Core() {
		registrationServer := &segreggrpc.RegistrationServer{
			LocalIA: topo.IA(),
			SegHandler: seghandler.Handler{
				Verifier: &seghandler.DefaultVerifier{
					Verifier: verifier,
				},
				Storage: &seghandler.DefaultStorage{
					PathDB:   pathDB,
					RevCache: revCache,
				},
			},
			Registrations: libmetrics.NewPromCounter(metrics.SegmentRegistrationsTotal),
		}
		cppb.RegisterSegmentRegistrationServiceServer(quicServer, registrationServer)
		connectInter.Handle(cpconnect.NewSegmentRegistrationServiceHandler(
			segregconnect.RegistrationServer{RegistrationServer: registrationServer},
		))
	}

	ctxSigner, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	signer := cs.NewSigner(ctxSigner, topo.IA(), trustDB, globalCfg.General.ConfigDir)

	var chainBuilder renewal.ChainBuilder
	var caClient *caapi.Client
	var caHealthCached *cachedCAHealth
	if globalCfg.CA.Mode != config.Disabled {
		renewalGauges := libmetrics.NewPromGauge(metrics.RenewalRegisteredHandlers)
		libmetrics.GaugeWith(renewalGauges, "type", "legacy").Set(0)
		libmetrics.GaugeWith(renewalGauges, "type", "in-process").Set(0)
		libmetrics.GaugeWith(renewalGauges, "type", "delegating").Set(0)
		srvCtr := libmetrics.NewPromCounter(metrics.RenewalServerRequestsTotal)
		renewalServer := &renewalgrpc.RenewalServer{
			IA:        topo.IA(),
			CMSSigner: signer,
			Metrics: renewalgrpc.RenewalServerMetrics{
				Success:       srvCtr.With(prom.LabelResult, prom.Success),
				BackendErrors: srvCtr.With(prom.LabelResult, prom.StatusErr),
			},
		}

		switch globalCfg.CA.Mode {
		case config.InProcess:
			libmetrics.GaugeWith(renewalGauges, "type", "in-process").Set(1)
			cmsCtr := libmetrics.CounterWith(
				libmetrics.NewPromCounter(metrics.RenewalHandledRequestsTotal),
				"type", "in-process",
			)
			chainBuilder = cs.NewChainBuilder(
				cs.ChainBuilderConfig{
					IA:                   topo.IA(),
					DB:                   trustDB,
					MaxValidity:          globalCfg.CA.MaxASValidity.Duration,
					ConfigDir:            globalCfg.General.ConfigDir,
					Metrics:              metrics.RenewalMetrics,
					ForceECDSAWithSHA512: !globalCfg.Features.AppropriateDigest,
				},
			)

			renewalServer.CMSHandler = &renewalgrpc.CMS{
				IA:           topo.IA(),
				ChainBuilder: chainBuilder,
				Verifier: renewal.RequestVerifier{
					TRCFetcher: trustDB,
				},
				Metrics: renewalgrpc.CMSHandlerMetrics{
					Success:       cmsCtr.With(prom.LabelResult, prom.Success),
					DatabaseError: cmsCtr.With(prom.LabelResult, prom.ErrDB),
					InternalError: cmsCtr.With(prom.LabelResult, prom.ErrInternal),
					NotFoundError: cmsCtr.With(prom.LabelResult, prom.ErrNotFound),
					ParseError:    cmsCtr.With(prom.LabelResult, prom.ErrParse),
					VerifyError:   cmsCtr.With(prom.LabelResult, prom.ErrVerify),
				},
			}
		case config.Delegating:
			libmetrics.GaugeWith(renewalGauges, "type", "delegating").Set(1)
			delCtr := libmetrics.CounterWith(
				libmetrics.NewPromCounter(metrics.RenewalHandledRequestsTotal),
				"type", "delegating",
			)
			sharedSecret := caconfig.NewPEMSymmetricKey(globalCfg.CA.Service.SharedSecret)
			subject := globalCfg.General.ID
			if globalCfg.CA.Service.ClientID != "" {
				subject = globalCfg.CA.Service.ClientID
			}
			caClient = &caapi.Client{
				Server: globalCfg.CA.Service.Address,
				Client: jwtauth.NewHTTPClient(
					&jwtauth.JWTTokenSource{
						Subject:   subject,
						Generator: sharedSecret.Get,
						Lifetime:  globalCfg.CA.Service.Lifetime.Duration,
					},
				),
			}
			caHealthCached = &cachedCAHealth{status: api.Unavailable}
			caHealthGauge := libmetrics.NewPromGauge(metrics.CAHealth)
			updateCAHealthMetrics(caHealthGauge, api.Unavailable)
			renewalServer.CMSHandler = &renewalgrpc.DelegatingHandler{
				Client: caClient,
				Metrics: renewalgrpc.DelegatingHandlerMetrics{
					BadRequests: libmetrics.CounterWith(delCtr,
						prom.LabelResult, prom.ErrInvalidReq),
					InternalError: libmetrics.CounterWith(delCtr,
						prom.LabelResult, prom.ErrInternal),
					Unavailable: libmetrics.CounterWith(delCtr,
						prom.LabelResult, prom.ErrUnavailable),
					Success: libmetrics.CounterWith(delCtr,
						prom.LabelResult, prom.Success),
				},
			}
			// Periodically check the connection to the CA backend
			// SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
			//nolint:staticcheck
			caHealthChecker := periodic.Start(
				periodic.Func{
					TaskName: "ca healthcheck",
					Task: func(ctx context.Context) {
						status, err := getCAHealth(ctx, caClient)
						if err != nil {
							log.Info("Failed to check the CA health status",
								"err", err,
								"server", caClient.Server,
							)
							updateCAHealthMetrics(caHealthGauge, api.Unavailable)
							caHealthCached.SetStatus(api.Unavailable)
							return
						}
						updateCAHealthMetrics(caHealthGauge, status)
						caHealthCached.SetStatus(status)
					},
				},
				30*time.Second,
				10*time.Second,
			)
			caHealthChecker.TriggerRun()
		default:
			return serrors.New("unsupported CA handler", "mode", globalCfg.CA.Mode)
		}

		cppb.RegisterChainRenewalServiceServer(quicServer, renewalServer)
		connectInter.Handle(cpconnect.NewChainRenewalServiceHandler(renewalconnect.RenewalServer{
			RenewalServer: renewalServer,
		}))
		connectIntra.Handle(cpconnect.NewChainRenewalServiceHandler(renewalconnect.RenewalServer{
			RenewalServer: renewalServer,
		}))
	}

	// Frequently regenerate signers to catch problems, and update the metrics.
	//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
	periodic.Start(
		periodic.Func{
			TaskName: "signer generator",
			Task: func(ctx context.Context) {
				if _, err := signer.Sign(ctx, []byte{}); err != nil {
					log.Info("Failed signer health check", "err", err)
				}
				if chainBuilder.PolicyGen != nil {
					if _, err := chainBuilder.PolicyGen.Generate(ctx); err != nil {
						log.Info("Failed renewal signer health check", "err", err)
					}
				}
			},
		},
		10*time.Second,
		5*time.Second,
	)

	//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
	trcRunner := periodic.Start(
		periodic.Func{
			TaskName: "trc expiration updater",
			Task: func(ctx context.Context) {
				trc, err := provider.GetSignedTRC(ctx,
					cppki.TRCID{
						ISD:    topo.IA().ISD(),
						Serial: scrypto.LatestVer,
						Base:   scrypto.LatestVer,
					},
					trust.AllowInactive(),
				)
				if err != nil {
					log.Info("Cannot resolve TRC for local ISD", "err", err)
					return
				}
				metrics.TrustLatestTRCNotBefore.Set(
					libmetrics.Timestamp(trc.TRC.Validity.NotBefore))
				metrics.TrustLatestTRCNotAfter.Set(libmetrics.Timestamp(trc.TRC.Validity.NotAfter))
				metrics.TrustLatestTRCSerial.Set(float64(trc.TRC.ID.Serial))
			},
		},
		10*time.Second,
		5*time.Second,
	)
	trcRunner.TriggerRun()

	ds := discovery.Topology{
		Information: topo,
		Requests:    libmetrics.NewPromCounter(metrics.DiscoveryRequestsTotal),
	}
	dpb.RegisterDiscoveryServiceServer(quicServer, ds)
	connectInter.Handle(
		dconnect.NewDiscoveryServiceHandler(discoveryconnect.Topology{Topology: ds}),
	)

	hpCfg := cs.HiddenPathConfigurator{
		LocalIA:           topo.IA(),
		Verifier:          verifier,
		Signer:            signer,
		PathDB:            pathDB,
		Dialer:            dialer,
		FetcherConfig:     fetcherCfg,
		IntraASTCPServer:  connectIntra,
		InterASQUICServer: quicServer,
	}
	hpWriterCfg, err := hpCfg.Setup(globalCfg.PS.HiddenPathsCfg)
	if err != nil {
		return err
	}

	// DRKey feature
	var drkeyEngine *drkey.ServiceEngine
	var epochDuration time.Duration
	if globalCfg.DRKey.Enabled() {
		epochDuration = drkeyutil.LoadEpochDuration()
		log.Debug("DRKey debug info", "epoch duration", epochDuration.String())
		masterKey, err := loadMasterSecret(globalCfg.General.ConfigDir)
		if err != nil {
			return serrors.Wrap("loading master secret in DRKey", err)
		}
		svBackend, err := storage.NewDRKeySecretValueStorage(globalCfg.DRKey.SecretValueDB)
		if err != nil {
			return serrors.Wrap("initializing Secret Value DB", err)
		}
		svCounter := libmetrics.NewPromCounter(metrics.DRKeySecretValueQueriesTotal)
		svDB := &secret.Database{
			Backend: svBackend,
			Metrics: &secret.Metrics{
				QueriesTotal: func(op, label string) libmetrics.Counter {
					return libmetrics.CounterWith(
						svCounter,
						"operation", op,
						prom.LabelResult, label)
				},
			},
		}
		defer svDB.Close()
		level1Backend, err := storage.NewDRKeyLevel1Storage(globalCfg.DRKey.Level1DB)
		if err != nil {
			return serrors.Wrap("initializing DRKey DB", err)
		}
		lvl1Counter := libmetrics.NewPromCounter(metrics.DRKeyLevel1QueriesTotal)
		level1DB := &level1.Database{
			Backend: level1Backend,
			Metrics: &level1.Metrics{
				QueriesTotal: func(op, label string) libmetrics.Counter {
					return libmetrics.CounterWith(
						lvl1Counter,
						"operation", op,
						prom.LabelResult, label)
				},
			},
		}
		defer level1DB.Close()

		drkeyFetcher := drkeyhappy.Fetcher{
			Connect: &drkeyconnect.Fetcher{
				Dialer: (&squic.EarlyDialerFactory{
					Transport: quicStack.Dialer.Transport,
					TLSConfig: libconnect.AdaptClientTLS(quicStack.Dialer.TLSConfig),
					Rewriter:  dialer.Rewriter,
				}).NewDialer,
				Router:     segreq.NewRouter(fetcherCfg),
				MaxRetries: 20,
			},
			Grpc: &drkeygrpc.Fetcher{
				Dialer: &libgrpc.QUICDialer{
					Rewriter: nc.AddressRewriter(),
					Dialer:   quicStack.Dialer,
				},
				Router:     segreq.NewRouter(fetcherCfg),
				MaxRetries: 20,
			},
		}
		prefetchKeeper, err := drkey.NewLevel1ARC(globalCfg.DRKey.PrefetchEntries)
		if err != nil {
			return err
		}
		drkeyEngine = &drkey.ServiceEngine{
			SecretBackend:  drkey.NewSecretValueBackend(svDB, masterKey.Key0, epochDuration),
			LocalIA:        topo.IA(),
			DB:             level1DB,
			Fetcher:        &drkeyFetcher,
			PrefetchKeeper: prefetchKeeper,
		}
		drkeyService := &drkeygrpc.Server{
			LocalIA:                   topo.IA(),
			ClientCertificateVerifier: nc.QUIC.TLSVerifier,
			Engine:                    drkeyEngine,
			AllowedSVHostProto:        globalCfg.DRKey.Delegation.ToAllowedSet(),
		}
		cppb.RegisterDRKeyInterServiceServer(quicServer, drkeyService)
		connectInter.Handle(cpconnect.NewDRKeyInterServiceHandler(drkeyconnect.Server{
			Server: drkeyService,
		}))
		connectIntra.Handle(cpconnect.NewDRKeyIntraServiceHandler(drkeyconnect.Server{
			Server: drkeyService,
		}))
		log.Info("DRKey is enabled")
	} else {
		log.Info("DRKey is DISABLED by configuration")
	}

	promgrpc.Register(quicServer)

	var cleanup app.Cleanup
	connectServer := http3.Server{
		Handler: libconnect.AttachPeer(connectInter),
	}

	grpcConns := make(chan *quic.Conn)
	//nolint:contextcheck // false positive.
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
	//nolint:contextcheck // false positive.
	cleanup.Add(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if err := intraServer.Shutdown(ctx); err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	})

	if globalCfg.API.Addr != "" {
		r := chi.NewRouter()
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins: []string{"*"},
		}))
		r.Get("/", api.ServeSpecInteractive)
		r.Get("/openapi.json", api.ServeSpecJSON)
		server := api.Server{
			SegmentsServer: segapi.Server{
				Segments: pathDB,
			},
			CPPKIServer: cppkiapi.Server{
				TrustDB: trustDB,
			},
			Beacons:  beaconDB,
			CA:       chainBuilder,
			Config:   service.NewConfigStatusPage(globalCfg).Handler,
			Info:     service.NewInfoStatusPage().Handler,
			LogLevel: service.NewLogLevelStatusPage().Handler,
			Signer:   signer,
			Topology: topo.HandleHTTP,
			Healther: &healther{
				Signer:   signer,
				TrustDB:  trustDB,
				ISD:      topo.IA().ISD(),
				CAHealth: caHealthCached,
			},
		}
		log.Info("Exposing API", "addr", globalCfg.API.Addr)
		s := http.Server{
			Addr:    globalCfg.API.Addr,
			Handler: api.HandlerFromMuxWithBaseURL(&server, r, "/api/v1"),
		}
		g.Go(func() error {
			defer log.HandlePanic()
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return serrors.Wrap("serving service management API", err)
			}
			return nil
		})
		cleanup.Add(s.Close)
	}
	err = cs.RegisterHTTPEndpoints(
		globalCfg.General.ID,
		&globalCfg,
		signer,
		chainBuilder,
		topo,
	)
	if err != nil {
		return err
	}

	staticInfo, err := beaconing.ParseStaticInfoCfg(globalCfg.General.StaticInfoConfig())
	if err != nil {
		log.Info("No static info file found. Static info settings disabled.", "err", err)
	}

	var propagationFilter func(intf *ifstate.Interface) bool
	if topo.Core() {
		propagationFilter = func(intf *ifstate.Interface) bool {
			topoInfo := intf.TopoInfo()
			return topoInfo.LinkType == topology.Core
		}
	} else {
		propagationFilter = func(intf *ifstate.Interface) bool {
			topoInfo := intf.TopoInfo()
			return topoInfo.LinkType == topology.Child
		}
	}

	originationFilter := func(intf *ifstate.Interface) bool {
		topoInfo := intf.TopoInfo()
		return topoInfo.LinkType == topology.Core || topoInfo.LinkType == topology.Child
	}

	rpc := &happy.Registrar{
		Connect: beaconingconnect.Registrar{
			Dialer: (&squic.EarlyDialerFactory{
				Transport: quicStack.InsecureDialer.Transport,
				TLSConfig: func() *tls.Config {
					cfg := quicStack.InsecureDialer.TLSConfig.Clone()
					cfg.NextProtos = []string{"h3", "SCION"}
					return cfg
				}(),
				Rewriter: dialer.Rewriter,
			}).NewDialer,
		},
		Grpc: beaconinggrpc.Registrar{Dialer: dialer},
	}
	tc := cs.TasksConfig{
		IA:            topo.IA(),
		Core:          topo.Core(),
		MTU:           topo.MTU(),
		Public:        nc.Public,
		AllInterfaces: intfs,
		PropagationInterfaces: func() []*ifstate.Interface {
			return intfs.Filtered(propagationFilter)
		},
		OriginationInterfaces: func() []*ifstate.Interface {
			return intfs.Filtered(originationFilter)
		},
		TrustDB:  trustDB,
		PathDB:   pathDB,
		RevCache: revCache,
		BeaconSenderFactory: &happy.BeaconSenderFactory{
			Connect: &beaconingconnect.BeaconSenderFactory{
				Dialer: (&squic.EarlyDialerFactory{
					Transport: quicStack.InsecureDialer.Transport,
					TLSConfig: func() *tls.Config {
						cfg := quicStack.InsecureDialer.TLSConfig.Clone()
						cfg.NextProtos = []string{"h3", "SCION"}
						return cfg
					}(),
					Rewriter: dialer.Rewriter,
				}).NewDialer,
			},
			Grpc: &beaconinggrpc.BeaconSenderFactory{
				Dialer: dialer,
			},
		},
		SegmentRegister: rpc,
		BeaconStore:     beaconStore,
		SignerGen: beaconing.SignerGenFunc(func(ctx context.Context) ([]beaconing.Signer, error) {
			signers, err := signer.SignerGen.Generate(ctx)
			if err != nil {
				return nil, err
			}
			if len(signers) == 0 {
				return nil, nil
			}
			r := make([]beaconing.Signer, 0, len(signers))
			for _, s := range signers {
				r = append(r, s)
			}
			return r, nil
		}),
		Inspector:   inspector,
		Metrics:     metrics,
		DRKeyEngine: drkeyEngine,
		MACGen:      macGen,
		NextHopper:  topo,
		StaticInfo:  func() *beaconing.StaticInfoCfg { return staticInfo },

		DiscoveryInfo: func() *discoveryext.Extension {
			cses := topo.ControlServiceAddresses()
			addrs := make([]netip.AddrPort, 0, len(cses))
			for _, cs := range cses {
				addrs = append(addrs, cs.AddrPort())
			}
			return &discoveryext.Extension{
				ControlServices:   addrs,
				DiscoveryServices: addrs,
			}
		},

		OriginationInterval:       globalCfg.BS.OriginationInterval.Duration,
		PropagationInterval:       globalCfg.BS.PropagationInterval.Duration,
		RegistrationInterval:      globalCfg.BS.RegistrationInterval.Duration,
		DRKeyEpochInterval:        epochDuration,
		HiddenPathRegistrationCfg: hpWriterCfg,
		AllowIsdLoop:              isdLoopAllowed,
		EPIC:                      globalCfg.BS.EPIC,
	}

	var internalErr, registered libmetrics.Counter
	if metrics != nil {
		internalErr = libmetrics.NewPromCounter(metrics.BeaconingRegistrarInternalErrorsTotal)
		registered = libmetrics.NewPromCounter(metrics.BeaconingRegisteredTotal)
	}

	pather := addrutil.Pather{
		NextHopper: topo,
	}
	// initialize the plugins
	localPlugin := &beaconing.LocalSegmentRegistrationPlugin{
		InternalErrors: internalErr,
		Registered:     registered,
		Store:          &seghandler.DefaultStorage{PathDB: pathDB},
	}
	remotePlugin := &beaconing.RemoteSegmentRegistrationPlugin{
		InternalErrors: internalErr,
		Registered:     registered,
		RPC:            rpc,
		Pather:         pather,
	}
	var hiddenPathPlugin *hiddenpath.HiddenSegmentRegistrationPlugin
	// Construct the hidden path plugin if the hidden path configuration exists.
	if hpWriterCfg != nil {
		hiddenPathPlugin = &hiddenpath.HiddenSegmentRegistrationPlugin{
			InternalErrors:     internalErr,
			Registered:         registered,
			Pather:             pather,
			RegistrationPolicy: hpWriterCfg.Policy,
			RPC:                hpWriterCfg.RPC,
			AddressResolver: hiddenpath.RegistrationResolver{
				Router:     hpWriterCfg.Router,
				Discoverer: hpWriterCfg.Discoverer,
			},
		}
	}
	ignorePlugin := &segreg.IgnoreSegmentRegistrationPlugin{}
	defaultPlugin := &DefaultSegmentRegistrationPlugin{
		LocalPlugin:  localPlugin,
		RemotePlugin: remotePlugin,
		HiddenPlugin: hiddenPathPlugin,
	}
	// plugins is a list of plugins that can be used to register segments.
	plugins := []segreg.SegmentRegistrationPlugin{
		localPlugin,
		remotePlugin,
		ignorePlugin,
		defaultPlugin,
	}
	if hiddenPathPlugin != nil {
		plugins = append(plugins, hiddenPathPlugin)
	}

	// Register the plugins so that they can be used everywhere.
	for _, plugin := range plugins {
		segreg.RegisterSegmentRegPlugin(plugin)
	}
	if err := tc.InitPlugins(errCtx, policies.RegistrationPolicies()); err != nil {
		return serrors.Wrap("initializing tasks plugins", err)
	}
	tasks, err := cs.StartTasks(tc)
	if err != nil {
		return serrors.Wrap("starting periodic tasks", err)
	}
	defer tasks.Kill()
	log.Info("Started periodic tasks")

	g.Go(func() error {
		defer log.HandlePanic()
		return globalCfg.Metrics.ServePrometheus(errCtx)
	})

	g.Go(func() error {
		defer log.HandlePanic()
		<-errCtx.Done()
		return cleanup.Do()
	})

	return g.Wait()
}

// loadedPolicies is a struct that holds the loaded policies.
// It can either be core policies or non-core policies, but not both.
type loadedPolicies struct {
	CorePolicies    *beacon.CorePolicies
	NonCorePolicies *beacon.Policies
}

// loadPolicies loads the policies based on the given policyConfig and
// the core flag, which must be true iff the service is core.
func loadPolicies(
	core bool,
	policyConfig config.Policies,
) (loadedPolicies, error) {
	if core {
		policies, err := cs.LoadCorePolicies(policyConfig)
		if err != nil {
			return loadedPolicies{}, serrors.Wrap("loading core policies", err)
		}
		return loadedPolicies{CorePolicies: &policies}, nil
	} else {
		policies, err := cs.LoadNonCorePolicies(policyConfig)
		if err != nil {
			return loadedPolicies{}, serrors.Wrap("loading non-core policies", err)
		}
		return loadedPolicies{NonCorePolicies: &policies}, nil
	}
}

// RegistrationPolicies returns the policies that are used for segment registration.
func (l loadedPolicies) RegistrationPolicies() []beacon.Policy {
	switch {
	case l.CorePolicies != nil:
		return []beacon.Policy{l.CorePolicies.CoreReg}
	case l.NonCorePolicies != nil:
		return []beacon.Policy{l.NonCorePolicies.UpReg, l.NonCorePolicies.DownReg}
	default:
		return nil
	}
}

func createBeaconStore(
	policies loadedPolicies,
	db storage.BeaconDB,
	provider beacon.ChainProvider,
) (cs.Store, bool, error) {
	switch {
	case policies.CorePolicies != nil:
		policies := policies.CorePolicies
		store, err := beacon.NewCoreBeaconStore(*policies, db, beacon.WithCheckChain(provider))
		return store, *policies.Prop.Filter.AllowIsdLoop, err
	case policies.NonCorePolicies != nil:
		policies := policies.NonCorePolicies
		store, err := beacon.NewBeaconStore(*policies, db, beacon.WithCheckChain(provider))
		return store, *policies.Prop.Filter.AllowIsdLoop, err
	default:
		return nil, false, serrors.New("no policies loaded")
	}
}

func adaptInterfaceMap(in map[iface.ID]topology.IFInfo) map[uint16]ifstate.InterfaceInfo {
	converted := make(map[uint16]ifstate.InterfaceInfo, len(in))
	for id, info := range in {
		converted[uint16(id)] = ifstate.InterfaceInfo{
			ID:           uint16(info.ID),
			IA:           info.IA,
			LinkType:     info.LinkType,
			InternalAddr: info.InternalAddr,
			RemoteID:     uint16(info.RemoteIfID),
			MTU:          uint16(info.MTU),
		}
	}
	return converted
}

type cachedCAHealth struct {
	status api.CAHealthStatus
	mtx    sync.Mutex
}

func (c *cachedCAHealth) SetStatus(status api.CAHealthStatus) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.status = status
}

func (c *cachedCAHealth) GetStatus() api.CAHealthStatus {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	return c.status
}

type healther struct {
	Signer   cstrust.RenewingSigner
	TrustDB  storage.TrustDB
	ISD      addr.ISD
	CAHealth *cachedCAHealth
}

func (h *healther) GetSignerHealth(ctx context.Context) api.SignerHealthData {
	signers, err := h.Signer.SignerGen.Generate(ctx)
	if err != nil {
		return api.SignerHealthData{
			SignerMissing:       true,
			SignerMissingDetail: err.Error(),
		}
	}
	now := time.Now()
	signer, err := trust.LastExpiring(signers, cppki.Validity{
		NotBefore: now,
		NotAfter:  now,
	})
	if err != nil {
		return api.SignerHealthData{
			SignerMissing:       true,
			SignerMissingDetail: err.Error(),
		}
	}
	return api.SignerHealthData{
		Expiration: signer.Expiration,
		InGrace:    signer.InGrace,
	}
}

func (h *healther) GetTRCHealth(ctx context.Context) api.TRCHealthData {
	trc, err := h.TrustDB.SignedTRC(ctx, cppki.TRCID{ISD: h.ISD})
	if err != nil {
		return api.TRCHealthData{
			TRCNotFound:       true,
			TRCNotFoundDetail: err.Error(),
		}
	}
	if trc.IsZero() {
		return api.TRCHealthData{
			TRCNotFound: true,
		}
	}
	return api.TRCHealthData{
		TRCID: trc.TRC.ID,
	}
}

func (h *healther) GetCAHealth(ctx context.Context) (api.CAHealthStatus, bool) {
	if h.CAHealth != nil {
		return h.CAHealth.GetStatus(), true
	}
	return api.Unavailable, false
}

func adaptTopology(topo *topology.Loader) snet.Topology {
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
}

func getCAHealth(
	ctx context.Context,
	caClient *caapi.Client,
) (api.CAHealthStatus, error) {
	logger := log.FromCtx(ctx)
	rep, err := caClient.GetHealthcheck(ctx)
	if err != nil {
		logger.Info("Request to CA service failed", "err", err)
		return api.Unavailable, serrors.New(
			"querying CA service health status",
			"err", err,
		)
	}
	defer rep.Body.Close()
	if rep.StatusCode != http.StatusOK {
		return api.Unavailable, serrors.New(
			"Status code of response was not OK",
			"status code", rep.Status,
		)
	}
	var r caapi.HealthCheckStatus
	if err := json.NewDecoder(rep.Body).Decode(&r); err != nil {
		logger.Info("Error reading CA service response", "err", err)
		return api.Unavailable, serrors.New(
			"reading CA service response",
			"err", err,
		)
	}
	return api.CAHealthStatus(r.Status), nil
}

func updateCAHealthMetrics(caHealthGauge libmetrics.Gauge, caStatus api.CAHealthStatus) {
	potentialCAStatus := []string{
		"available",
		"unavailable",
		"starting",
		"stopping",
	}
	libmetrics.GaugeWith(caHealthGauge, "status", string(caStatus)).Set(1)
	for _, status := range potentialCAStatus {
		if strings.ToLower(string(caStatus)) != status {
			libmetrics.GaugeWith(caHealthGauge, "status", status).Set(0)
		}
	}
}

func loadMasterSecret(dir string) (keyconf.Master, error) {
	masterKey, err := keyconf.LoadMaster(filepath.Join(dir, "keys"))
	if err != nil {
		return keyconf.Master{}, serrors.Wrap("error getting master secret", err)
	}
	return masterKey, nil
}
