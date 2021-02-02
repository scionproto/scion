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
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/cors"
	promgrpc "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing"
	beaconinggrpc "github.com/scionproto/scion/go/cs/beaconing/grpc"
	"github.com/scionproto/scion/go/cs/config"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/onehop"
	segreggrpc "github.com/scionproto/scion/go/cs/segreg/grpc"
	"github.com/scionproto/scion/go/cs/segreq"
	segreqgrpc "github.com/scionproto/scion/go/cs/segreq/grpc"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	segfetchergrpc "github.com/scionproto/scion/go/lib/infra/modules/segfetcher/grpc"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/log"
	libmetrics "github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/app/launcher"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/pkg/cs"
	"github.com/scionproto/scion/go/pkg/cs/api"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
	cstrustgrpc "github.com/scionproto/scion/go/pkg/cs/trust/grpc"
	cstrustmetrics "github.com/scionproto/scion/go/pkg/cs/trust/metrics"
	"github.com/scionproto/scion/go/pkg/discovery"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	dpb "github.com/scionproto/scion/go/pkg/proto/discovery"
	"github.com/scionproto/scion/go/pkg/service"
	"github.com/scionproto/scion/go/pkg/storage"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/compat"
	trustgrpc "github.com/scionproto/scion/go/pkg/trust/grpc"
	trustmetrics "github.com/scionproto/scion/go/pkg/trust/metrics"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
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

func realMain() error {
	metrics := cs.NewMetrics()

	intfs, err := setup(&globalCfg)
	if err != nil {
		return err
	}
	topo := itopo.Get()

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
	pathDB = pathdb.WithMetrics(string(storage.BackendSqlite), pathDB)
	defer pathDB.Close()

	nc := infraenv.NetworkConfig{
		IA:                    topo.IA(),
		Public:                topo.PublicAddress(addr.SvcCS, globalCfg.General.ID),
		ReconnectToDispatcher: globalCfg.General.ReconnectToDispatcher,
		QUIC: infraenv.QUIC{
			Address: globalCfg.QUIC.Address,
		},
		SVCRouter: messenger.NewSVCRouter(itopo.Provider()),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: cs.RevocationHandler{RevCache: revCache},
		},
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
		Rewriter: nc.AddressRewriter(nil),
		Dialer:   quicStack.Dialer,
	}

	trustDB, err := storage.NewTrustStorage(globalCfg.TrustDB)
	if err != nil {
		return serrors.WrapStr("initializing trust storage", err)
	}
	trustDB = trustmetrics.WrapDB(string(storage.BackendSqlite), trustDB)
	defer trustDB.Close()
	if err := cs.LoadTrustMaterial(globalCfg.General.ConfigDir, trustDB, log.Root()); err != nil {
		return err
	}

	beaconStore, isdLoopAllowed, err := loadBeaconStore(topo.Core(), topo.IA(), globalCfg)
	if err != nil {
		return serrors.WrapStr("initializing beacon store", err)
	}
	defer beaconStore.Close()

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
		PathDB:        pathDB,
		RevCache:      revCache,
		QueryInterval: globalCfg.PS.QueryInterval.Duration,
		RPC: &segfetchergrpc.Requester{
			Dialer: dialer,
		},
		Inspector:    inspector,
		TopoProvider: itopo.Provider(),
		Verifier:     verifier,
	}
	provider.Router = trust.AuthRouter{
		ISD:    topo.IA().I,
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

	var chainBuilder cstrust.ChainBuilder
	if topo.CA() {
		renewalDB, err := storage.NewRenewalStorage(globalCfg.RenewalDB)
		if err != nil {
			return serrors.WrapStr("initializing renewal database", err)
		}
		defer renewalDB.Close()
		if err := cs.LoadClientChains(renewalDB, globalCfg.General.ConfigDir); err != nil {
			return serrors.WrapStr("loading client certificate chains", err)
		}
		chainBuilder = cs.NewChainBuilder(
			topo.IA(),
			trustDB,
			globalCfg.CA.MaxASValidity.Duration,
			globalCfg.General.ConfigDir,
		)
		renewalServer := &cstrustgrpc.RenewalServer{
			Verifier:     cstrustgrpc.RenewalRequestVerifierFunc(renewal.VerifyChainRenewalRequest),
			ChainBuilder: chainBuilder,
			DB:           renewalDB,
			IA:           topo.IA(),
			Signer:       signer,
			Requests:     libmetrics.NewPromCounter(cstrustmetrics.Handler.Requests),
		}
		cppb.RegisterChainRenewalServiceServer(quicServer, renewalServer)
		cppb.RegisterChainRenewalServiceServer(tcpServer, renewalServer)

		periodic.Start(
			periodic.Func{
				TaskName: "update client certificates from disk",
				Task: func(ctx context.Context) {
					err := cs.LoadClientChains(renewalDB, globalCfg.General.ConfigDir)
					if err != nil {
						log.Debug("loading client certificate chains", "error", err)
					}
				},
			},
			30*time.Second,
			5*time.Second,
		)
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
						ISD:    topo.IA().I,
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
		Provider: itopo.Provider(),
		Requests: libmetrics.NewPromCounter(metrics.DiscoveryRequestsTotal),
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

	promgrpc.Register(quicServer)
	promgrpc.Register(tcpServer)
	go func() {
		defer log.HandlePanic()
		if err := quicServer.Serve(quicStack.Listener); err != nil {
			fatal.Fatal(err)
		}
	}()
	go func() {
		defer log.HandlePanic()
		if err := tcpServer.Serve(tcpStack); err != nil {
			fatal.Fatal(err)
		}
	}()
	if globalCfg.API.Addr != "" {
		r := chi.NewRouter()
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins: []string{"*"},
		}))
		server := api.Server{
			CA:       chainBuilder,
			Config:   service.NewConfigHandler(globalCfg),
			Info:     service.NewInfoHandler(),
			LogLevel: log.ConsoleLevel.ServeHTTP,
			Signer:   signer,
			Topology: itopo.TopologyHandler,
		}
		log.Info("Exposing API", "addr", globalCfg.API.Addr)
		h := api.HandlerFromMux(&server, r)
		go func() {
			defer log.HandlePanic()
			if err := http.ListenAndServe(globalCfg.API.Addr, h); err != nil {
				fatal.Fatal(serrors.WrapStr("serving HTTP API", err))
			}
		}()
	}
	err = cs.StartHTTPEndpoints(globalCfg.General.ID, globalCfg, signer, chainBuilder,
		globalCfg.Metrics)
	if err != nil {
		return serrors.WrapStr("registering status pages", err)
	}
	ohpConn, err := cs.NewOneHopConn(topo.IA(), nc.Public, "",
		globalCfg.General.ReconnectToDispatcher)
	if err != nil {
		return serrors.WrapStr("creating one-hop connection", err)
	}
	macGen, err := cs.MACGenFactory(globalCfg.General.ConfigDir)
	if err != nil {
		return err
	}
	staticInfo, err := beaconing.ParseStaticInfoCfg(globalCfg.General.StaticInfoConfig())
	if err != nil {
		log.Info("No static info file found. Static info settings disabled.", "err", err)
	}

	addressRewriter := nc.AddressRewriter(
		&onehop.OHPPacketDispatcherService{
			PacketDispatcherService: &snet.DefaultPacketDispatcherService{
				Dispatcher: reliable.NewDispatcher(""),
			},
		},
	)
	tasks, err := cs.StartTasks(cs.TasksConfig{
		Public:   nc.Public,
		Intfs:    intfs,
		TrustDB:  trustDB,
		PathDB:   pathDB,
		RevCache: revCache,
		BeaconSender: &onehop.BeaconSender{
			Sender: onehop.Sender{
				Conn: ohpConn,
				IA:   topo.IA(),
				MAC:  macGen(),
				Addr: nc.Public,
			},
			AddressRewriter: addressRewriter,
			RPC: beaconinggrpc.BeaconSender{
				Dialer: dialer,
			},
		},
		SegmentRegister: beaconinggrpc.Registrar{Dialer: dialer},
		BeaconStore:     beaconStore,
		Signer:          signer,
		OneHopConn:      ohpConn,
		Inspector:       inspector,
		Metrics:         metrics,
		MACGen:          macGen,
		TopoProvider:    itopo.Provider(),
		StaticInfo:      func() *beaconing.StaticInfoCfg { return staticInfo },

		OriginationInterval:       globalCfg.BS.OriginationInterval.Duration,
		PropagationInterval:       globalCfg.BS.PropagationInterval.Duration,
		RegistrationInterval:      globalCfg.BS.RegistrationInterval.Duration,
		HiddenPathRegistrationCfg: hpWriterCfg,
		AllowIsdLoop:              isdLoopAllowed,
	})
	if err != nil {
		serrors.WrapStr("starting periodic tasks", err)
	}
	defer tasks.Kill()
	log.Info("Started periodic tasks")

	select {
	case <-fatal.ShutdownChan():
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		// Deferred shutdowns for all running servers run now.
		return nil
	case <-fatal.FatalChan():
		return serrors.New("shutdown on error")
	}
}

func setup(cfg *config.Config) (*ifstate.Interfaces, error) {
	topo, err := topology.FromJSONFile(cfg.General.Topology())
	if err != nil {
		return nil, serrors.WrapStr("loading topology", err)
	}
	intfs := ifstate.NewInterfaces(topo.IFInfoMap(), ifstate.Config{})
	itopo.Init(&itopo.Config{
		ID:  cfg.General.ID,
		Svc: topology.Control,
		Callbacks: itopo.Callbacks{
			OnUpdate: func() {
				intfs.Update(itopo.Get().IFInfoMap())
			},
		},
	})
	if err := itopo.Update(topo); err != nil {
		return nil, serrors.WrapStr("setting initial static topology", err)
	}
	infraenv.InitInfraEnvironment(cfg.General.Topology())
	return intfs, nil
}

func loadBeaconStore(core bool, ia addr.IA, cfg config.Config) (cs.Store, bool, error) {
	db, err := storage.NewBeaconStorage(cfg.BeaconDB, ia)
	if err != nil {
		return nil, false, err
	}
	db = beacon.DBWithMetrics(string(storage.BackendSqlite), db)
	if core {
		policies, err := cs.LoadCorePolicies(cfg.BS.Policies)
		if err != nil {
			return nil, false, err
		}
		store, err := beacon.NewCoreBeaconStore(policies, db)
		return store, *policies.Prop.Filter.AllowIsdLoop, err
	}
	policies, err := cs.LoadNonCorePolicies(cfg.BS.Policies)
	if err != nil {
		return nil, false, err
	}
	store, err := beacon.NewBeaconStore(policies, db)
	return store, *policies.Prop.Filter.AllowIsdLoop, err
}
