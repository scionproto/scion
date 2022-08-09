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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	promgrpc "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"inet.af/netaddr"

	cs "github.com/scionproto/scion/control"
	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	beaconinggrpc "github.com/scionproto/scion/control/beaconing/grpc"
	"github.com/scionproto/scion/control/config"
	"github.com/scionproto/scion/control/drkey"
	drkeygrpc "github.com/scionproto/scion/control/drkey/grpc"
	"github.com/scionproto/scion/control/ifstate"
	api "github.com/scionproto/scion/control/mgmtapi"
	"github.com/scionproto/scion/control/onehop"
	segreggrpc "github.com/scionproto/scion/control/segreg/grpc"
	"github.com/scionproto/scion/control/segreq"
	segreqgrpc "github.com/scionproto/scion/control/segreq/grpc"
	cstrust "github.com/scionproto/scion/control/trust"
	cstrustgrpc "github.com/scionproto/scion/control/trust/grpc"
	cstrustmetrics "github.com/scionproto/scion/control/trust/metrics"
	"github.com/scionproto/scion/pkg/addr"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	libmetrics "github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	dpb "github.com/scionproto/scion/pkg/proto/discovery"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app"
	infraenv "github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/app/launcher"
	caapi "github.com/scionproto/scion/private/ca/api"
	caconfig "github.com/scionproto/scion/private/ca/config"
	"github.com/scionproto/scion/private/ca/renewal"
	renewalgrpc "github.com/scionproto/scion/private/ca/renewal/grpc"
	"github.com/scionproto/scion/private/discovery"
	"github.com/scionproto/scion/private/keyconf"
	cppkiapi "github.com/scionproto/scion/private/mgmtapi/cppki/api"
	"github.com/scionproto/scion/private/mgmtapi/jwtauth"
	segapi "github.com/scionproto/scion/private/mgmtapi/segments/api"
	"github.com/scionproto/scion/private/periodic"
	segfetchergrpc "github.com/scionproto/scion/private/segment/segfetcher/grpc"
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
	trustgrpc "github.com/scionproto/scion/private/trust/grpc"
	trustmetrics "github.com/scionproto/scion/private/trust/metrics"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		TOMLConfig: &globalCfg,
		ShortName:  "SCION Control Service",
		// TODO(scrye): Deprecated additional sampler, remove once Anapaya/scion#5000 is in.
		Samplers: []func(command.Pather) *cobra.Command{newSamplePolicy},
		Main:     realMain,
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
		return serrors.WrapStr("creating topology loader", err)
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
		return serrors.WrapStr("initializing tracer", err)
	}
	defer closer.Close()

	revCache := storage.NewRevocationStorage()
	defer revCache.Close()
	pathDB, err := storage.NewPathStorage(globalCfg.PathDB)
	if err != nil {
		return serrors.WrapStr("initializing path storage", err)
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

	nc := infraenv.NetworkConfig{
		IA:                    topo.IA(),
		Public:                topo.ControlServiceAddress(globalCfg.General.ID),
		ReconnectToDispatcher: globalCfg.General.ReconnectToDispatcher,
		QUIC: infraenv.QUIC{
			Address: globalCfg.QUIC.Address,
		},
		SVCResolver: topo,
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: cs.RevocationHandler{RevCache: revCache},
			SCMPErrors:        metrics.SCMPErrors,
		},
		SCIONNetworkMetrics:    metrics.SCIONNetworkMetrics,
		SCIONPacketConnMetrics: metrics.SCIONPacketConnMetrics,
	}
	quicStack, err := nc.QUICStack()
	if err != nil {
		return serrors.WrapStr("initializing QUIC stack", err)
	}
	defer quicStack.RedirectCloser()
	tcpStack, err := nc.TCPStack()
	if err != nil {
		return serrors.WrapStr("initializing TCP stack", err)
	}
	dialer := &libgrpc.QUICDialer{
		Rewriter: &onehop.AddressRewriter{
			Rewriter: nc.AddressRewriter(nil),
			MAC:      macGen(),
		},
		Dialer: quicStack.Dialer,
	}

	trustDB, err := storage.NewTrustStorage(globalCfg.TrustDB)
	if err != nil {
		return serrors.WrapStr("initializing trust storage", err)
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

	beaconDB, err := storage.NewBeaconStorage(globalCfg.BeaconDB, topo.IA())
	if err != nil {
		return serrors.WrapStr("initializing beacon storage", err)
	}
	defer beaconDB.Close()
	beaconDB = beaconstoragemetrics.WrapDB(beaconDB, beaconstoragemetrics.Config{
		Driver:       string(storage.BackendSqlite),
		QueriesTotal: libmetrics.NewPromCounter(metrics.BeaconDBQueriesTotal),
	})

	beaconStore, isdLoopAllowed, err := createBeaconStore(
		beaconDB,
		topo.Core(),
		globalCfg.BS.Policies,
	)
	if err != nil {
		return serrors.WrapStr("initializing beacon store", err)
	}

	trustengineCache := globalCfg.TrustEngine.Cache.New()
	cacheHits := libmetrics.NewPromCounter(trustmetrics.CacheHitsTotal)
	inspector := trust.CachingInspector{
		Inspector: trust.DBInspector{
			DB: trustDB,
		},
		CacheHits:          cacheHits,
		MaxCacheExpiration: globalCfg.TrustEngine.Cache.Expiration,
		Cache:              trustengineCache,
	}
	provider := trust.FetchingProvider{
		DB: trustDB,
		Fetcher: trustgrpc.Fetcher{
			IA:       topo.IA(),
			Dialer:   dialer,
			Requests: libmetrics.NewPromCounter(trustmetrics.RPC.Fetches),
		},
		Recurser: trust.ASLocalRecurser{IA: topo.IA()},
		// XXX(roosd): cyclic dependency on router. It is set below.
	}
	verifier := compat.Verifier{
		Verifier: trust.Verifier{
			Engine:             provider,
			CacheHits:          cacheHits,
			MaxCacheExpiration: globalCfg.TrustEngine.Cache.Expiration,
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
		RPC: &segfetchergrpc.Requester{
			Dialer: dialer,
		},
		Inspector: inspector,
		Verifier:  verifier,
	}
	provider.Router = trust.AuthRouter{
		ISD:    topo.IA().ISD(),
		DB:     trustDB,
		Router: segreq.NewRouter(fetcherCfg),
	}

	quicServer := grpc.NewServer(libgrpc.UnaryServerInterceptor())
	tcpServer := grpc.NewServer(libgrpc.UnaryServerInterceptor())

	// Register trust material related handlers.
	trustServer := &cstrustgrpc.MaterialServer{
		Provider: provider,
		IA:       topo.IA(),
		Requests: libmetrics.NewPromCounter(cstrustmetrics.Handler.Requests),
	}
	cppb.RegisterTrustMaterialServiceServer(quicServer, trustServer)
	cppb.RegisterTrustMaterialServiceServer(tcpServer, trustServer)

	// Handle beaconing.
	cppb.RegisterSegmentCreationServiceServer(quicServer, &beaconinggrpc.SegmentCreationServer{
		Handler: &beaconing.Handler{
			LocalIA:        topo.IA(),
			Inserter:       beaconStore,
			Interfaces:     intfs,
			Verifier:       verifier,
			BeaconsHandled: libmetrics.NewPromCounter(metrics.BeaconingReceivedTotal),
		},
	})

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
	cppb.RegisterSegmentLookupServiceServer(tcpServer, forwardingLookupServer)
	if topo.Core() {
		cppb.RegisterSegmentLookupServiceServer(quicServer, authLookupServer)
	}

	// Handle segment registration.
	if topo.Core() {
		cppb.RegisterSegmentRegistrationServiceServer(quicServer, &segreggrpc.RegistrationServer{
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
		})

	}

	signer, err := cs.NewSigner(topo.IA(), trustDB, globalCfg.General.ConfigDir)
	if err != nil {
		return serrors.WrapStr("initializing AS signer", err)
	}

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
		cppb.RegisterChainRenewalServiceServer(tcpServer, renewalServer)
	}

	// Frequently regenerate signers to catch problems, and update the metrics.
	periodic.Start(
		periodic.Func{
			TaskName: "signer generator",
			Task: func(ctx context.Context) {
				signer.Sign(ctx, []byte{})
				if chainBuilder.PolicyGen != nil {
					chainBuilder.PolicyGen.Generate(ctx)
				}
			},
		},
		10*time.Second,
		5*time.Second,
	)

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

	dsHealth := health.NewServer()
	dsHealth.SetServingStatus("discovery", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(tcpServer, dsHealth)

	hpCfg := cs.HiddenPathConfigurator{
		LocalIA:           topo.IA(),
		Verifier:          verifier,
		Signer:            signer,
		PathDB:            pathDB,
		Dialer:            dialer,
		FetcherConfig:     fetcherCfg,
		IntraASTCPServer:  tcpServer,
		InterASQUICServer: quicServer,
	}
	hpWriterCfg, err := hpCfg.Setup(globalCfg.PS.HiddenPathsCfg)
	if err != nil {
		return err
	}

	// DRKey feature
	var drkeyEngine *drkey.ServiceEngine
	var quicTLSServer *grpc.Server
	var epochDuration time.Duration
	if globalCfg.DRKey.Enabled() {
		epochDuration, err = loadEpochDuration()
		if err != nil {
			return err
		}
		log.Debug("DRKey debug info", "epoch duration", epochDuration.String())
		masterKey, err := loadMasterSecret(globalCfg.General.ConfigDir)
		if err != nil {
			return serrors.WrapStr("loading master secret in DRKey", err)
		}
		svBackend, err := storage.NewDRKeySecretValueStorage(globalCfg.DRKey.SecretValueDB)
		if err != nil {
			return serrors.WrapStr("initializing Secret Value DB", err)
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
			return serrors.WrapStr("initializing DRKey DB", err)
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
		loader := trust.X509KeyPairProvider{
			IA: topo.IA(),
			DB: trustDB,
			KeyLoader: cstrust.LoadingRing{
				Dir: filepath.Join(globalCfg.General.ConfigDir, "crypto/as"),
			},
		}
		tlsMgr := trust.NewTLSCryptoManager(loader, trustDB)
		drkeyFetcher := drkeygrpc.Fetcher{
			Dialer: &libgrpc.TLSQUICDialer{
				QUICDialer: dialer,
				Credentials: credentials.NewTLS(&tls.Config{
					InsecureSkipVerify:    true,
					GetClientCertificate:  tlsMgr.GetClientCertificate,
					VerifyPeerCertificate: tlsMgr.VerifyServerCertificate,
					VerifyConnection:      tlsMgr.VerifyConnection,
				}),
			},
			Router:     segreq.NewRouter(fetcherCfg),
			MaxRetries: 20,
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
			LocalIA:            topo.IA(),
			Engine:             drkeyEngine,
			AllowedSVHostProto: globalCfg.DRKey.Delegation.ToAllowedSet(),
		}
		srvConfig := &tls.Config{
			InsecureSkipVerify:    true,
			GetCertificate:        tlsMgr.GetCertificate,
			VerifyPeerCertificate: tlsMgr.VerifyClientCertificate,
			ClientAuth:            tls.RequireAnyClientCert,
		}
		quicTLSServer = grpc.NewServer(
			grpc.Creds(credentials.NewTLS(srvConfig)),
			libgrpc.UnaryServerInterceptor(),
		)
		cppb.RegisterDRKeyInterServiceServer(quicTLSServer, drkeyService)
		cppb.RegisterDRKeyIntraServiceServer(tcpServer, drkeyService)
		log.Info("DRKey is enabled")
	} else {
		log.Info("DRKey is DISABLED by configuration")
	}

	promgrpc.Register(quicServer)
	promgrpc.Register(tcpServer)

	var cleanup app.Cleanup
	g.Go(func() error {
		defer log.HandlePanic()
		if err := quicServer.Serve(quicStack.Listener); err != nil {
			return serrors.WrapStr("serving gRPC/QUIC API", err)
		}
		return nil
	})
	cleanup.Add(func() error { quicServer.GracefulStop(); return nil })
	if quicTLSServer != nil {
		g.Go(func() error {
			defer log.HandlePanic()
			if err := quicTLSServer.Serve(quicStack.Listener); err != nil {
				return serrors.WrapStr("serving gRPC(TLS)/QUIC API", err)
			}
			return nil
		})
		cleanup.Add(func() error { quicTLSServer.GracefulStop(); return nil })
	}
	g.Go(func() error {
		defer log.HandlePanic()
		if err := tcpServer.Serve(tcpStack); err != nil {
			return serrors.WrapStr("serving gRPC/TCP API", err)
		}
		return nil
	})
	cleanup.Add(func() error { tcpServer.GracefulStop(); return nil })

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
				return serrors.WrapStr("serving service management API", err)
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

	tasks, err := cs.StartTasks(cs.TasksConfig{
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
		BeaconSenderFactory: &beaconinggrpc.BeaconSenderFactory{
			Dialer: dialer,
		},
		SegmentRegister: beaconinggrpc.Registrar{Dialer: dialer},
		BeaconStore:     beaconStore,
		Signer:          signer,
		Inspector:       inspector,
		Metrics:         metrics,
		DRKeyEngine:     drkeyEngine,
		MACGen:          macGen,
		NextHopper:      topo,
		StaticInfo:      func() *beaconing.StaticInfoCfg { return staticInfo },

		OriginationInterval:       globalCfg.BS.OriginationInterval.Duration,
		PropagationInterval:       globalCfg.BS.PropagationInterval.Duration,
		RegistrationInterval:      globalCfg.BS.RegistrationInterval.Duration,
		DRKeyEpochInterval:        epochDuration,
		HiddenPathRegistrationCfg: hpWriterCfg,
		AllowIsdLoop:              isdLoopAllowed,
		EPIC:                      globalCfg.BS.EPIC,
	})
	if err != nil {
		return serrors.WrapStr("starting periodic tasks", err)
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

func createBeaconStore(
	db storage.BeaconDB,
	core bool,
	policyConfig config.Policies,
) (cs.Store, bool, error) {

	if core {
		policies, err := cs.LoadCorePolicies(policyConfig)
		if err != nil {
			return nil, false, err
		}
		store, err := beacon.NewCoreBeaconStore(policies, db)
		return store, *policies.Prop.Filter.AllowIsdLoop, err
	}
	policies, err := cs.LoadNonCorePolicies(policyConfig)
	if err != nil {
		return nil, false, err
	}
	store, err := beacon.NewBeaconStore(policies, db)
	return store, *policies.Prop.Filter.AllowIsdLoop, err
}

func adaptInterfaceMap(in map[common.IFIDType]topology.IFInfo) map[uint16]ifstate.InterfaceInfo {
	converted := make(map[uint16]ifstate.InterfaceInfo, len(in))
	for id, info := range in {
		addr, ok := netaddr.FromStdAddr(
			info.InternalAddr.IP,
			info.InternalAddr.Port,
			info.InternalAddr.Zone,
		)
		if !ok {
			panic(fmt.Sprintf("failed to adapt the topology format. Input %s", info.InternalAddr))
		}
		converted[uint16(id)] = ifstate.InterfaceInfo{
			ID:           uint16(info.ID),
			IA:           info.IA,
			LinkType:     info.LinkType,
			InternalAddr: addr,
			RemoteID:     uint16(info.RemoteIFID),
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
	signer, err := h.Signer.SignerGen.Generate(ctx)
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

func getCAHealth(
	ctx context.Context,
	caClient *caapi.Client,
) (api.CAHealthStatus, error) {

	logger := log.FromCtx(ctx)
	rep, err := caClient.GetHealthcheck(ctx)
	if err != nil {
		logger.Info("Request to CA service failed", "err", err)
		return api.Unavailable, serrors.New(
			"querrying CA service health status",
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
		return keyconf.Master{}, serrors.WrapStr("error getting master secret", err)
	}
	return masterKey, nil
}

func loadEpochDuration() (time.Duration, error) {
	s := os.Getenv(config.EnvVarEpochDuration)
	if s == "" {
		return config.DefaultEpochDuration, nil
	}
	duration, err := util.ParseDuration(s)
	if err != nil {
		return 0, serrors.WrapStr("parsing SCION_TESTING_DRKEY_EPOCH_DURATION", err)
	}
	return duration, nil
}
