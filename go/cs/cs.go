// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	"github.com/scionproto/scion/go/lib/common"
	libconfig "github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
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
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/pkg/cs"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
	cstrustgrpc "github.com/scionproto/scion/go/pkg/cs/trust/grpc"
	cstrustmetrics "github.com/scionproto/scion/go/pkg/cs/trust/metrics"
	"github.com/scionproto/scion/go/pkg/discovery"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	dpb "github.com/scionproto/scion/go/pkg/proto/discovery"
	"github.com/scionproto/scion/go/pkg/storage"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/compat"
	trustgrpc "github.com/scionproto/scion/go/pkg/trust/grpc"
	trustmetrics "github.com/scionproto/scion/go/pkg/trust/metrics"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
)

func main() {
	var flags struct {
		config string
	}
	executable := filepath.Base(os.Args[0])
	cmd := &cobra.Command{
		Use:           executable,
		Short:         "SCION Control Service instance",
		Example:       "  " + executable + " --config cs.toml",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(flags.config)
		},
	}
	cmd.AddCommand(
		command.NewCompletion(cmd),
		command.NewSample(cmd,
			command.NewSampleConfig(&config.Config{}),
			newSamplePolicy,
		),
		command.NewVersion(cmd),
	)
	cmd.Flags().StringVar(&flags.config, "config", "", "Configuration file (required)")
	cmd.MarkFlagRequired("config")
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run(file string) error {
	fatal.Init()
	cfg, err := setupBasic(file)
	if err != nil {
		return err
	}
	defer log.Flush()
	defer env.LogAppStopped(common.CPService, cfg.General.ID)
	defer log.HandlePanic()
	metrics := cs.NewMetrics()

	intfs, err := setup(&cfg)
	if err != nil {
		return err
	}
	topo := itopo.Get()

	closer, err := cs.InitTracer(cfg.Tracing, cfg.General.ID)
	if err != nil {
		return serrors.WrapStr("initializing tracer", err)
	}
	defer closer.Close()

	revCache := storage.NewRevocationStorage()
	defer revCache.Close()
	pathDB, err := storage.NewPathStorage(cfg.PathDB)
	if err != nil {
		return serrors.WrapStr("initializing path storage", err)
	}
	pathDB = pathdb.WithMetrics(string(storage.BackendSqlite), pathDB)
	defer pathDB.Close()

	nc := infraenv.NetworkConfig{
		IA:                    topo.IA(),
		Public:                topo.PublicAddress(addr.SvcCS, cfg.General.ID),
		ReconnectToDispatcher: cfg.General.ReconnectToDispatcher,
		QUIC: infraenv.QUIC{
			Address: cfg.QUIC.Address,
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

	trustDB, err := storage.NewTrustStorage(cfg.TrustDB)
	if err != nil {
		return serrors.WrapStr("initializing trust storage", err)
	}
	trustDB = trustmetrics.WrapDB(string(storage.BackendSqlite), trustDB)
	defer trustDB.Close()
	if err := cs.LoadTrustMaterial(cfg.General.ConfigDir, trustDB, log.Root()); err != nil {
		return err
	}

	beaconStore, isdLoopAllowed, err := loadBeaconStore(topo.Core(), topo.IA(), cfg)
	if err != nil {
		return serrors.WrapStr("initializing beacon store", err)
	}
	defer beaconStore.Close()

	trustengineCache := cfg.TrustEngine.Cache.New()
	cacheHits := libmetrics.NewPromCounter(trustmetrics.CacheHitsTotal)
	inspector := trust.CachingInspector{
		Inspector: trust.DBInspector{
			DB: trustDB,
		},
		CacheHits:          cacheHits,
		MaxCacheExpiration: cfg.TrustEngine.Cache.Expiration,
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
			MaxCacheExpiration: cfg.TrustEngine.Cache.Expiration,
			Cache:              trustengineCache,
		},
	}
	fetcherCfg := segreq.FetcherConfig{
		IA:            topo.IA(),
		PathDB:        pathDB,
		RevCache:      revCache,
		QueryInterval: cfg.PS.QueryInterval.Duration,
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

	signer, err := cs.NewSigner(topo.IA(), trustDB, cfg.General.ConfigDir)
	if err != nil {
		return serrors.WrapStr("initializing AS signer", err)
	}

	var chainBuilder cstrust.ChainBuilder
	if topo.CA() {
		renewalDB, err := storage.NewRenewalStorage(cfg.RenewalDB)
		if err != nil {
			return serrors.WrapStr("initializing renewal database", err)
		}
		defer renewalDB.Close()
		if err := cs.LoadClientChains(renewalDB, cfg.General.ConfigDir); err != nil {
			return serrors.WrapStr("loading client certificate chains", err)
		}
		chainBuilder = cs.NewChainBuilder(
			topo.IA(),
			trustDB,
			cfg.CA.MaxASValidity.Duration,
			cfg.General.ConfigDir,
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
					if err := cs.LoadClientChains(renewalDB, cfg.General.ConfigDir); err != nil {
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

	ds := discovery.Topology{
		Provider: itopo.Provider(),
		Requests: libmetrics.NewPromCounter(metrics.DiscoveryRequestsTotal),
	}
	dpb.RegisterDiscoveryServiceServer(quicServer, ds)

	dsHealth := health.NewServer()
	dsHealth.SetServingStatus("discovery", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(tcpServer, dsHealth)

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

	err = cs.StartHTTPEndpoints(cfg.General.ID, cfg, signer, chainBuilder, cfg.Metrics)
	if err != nil {
		return serrors.WrapStr("registering status pages", err)
	}
	ohpConn, err := cs.NewOneHopConn(topo.IA(), nc.Public, "", cfg.General.ReconnectToDispatcher)
	if err != nil {
		return serrors.WrapStr("creating one-hop connection", err)
	}
	macGen, err := cs.MACGenFactory(cfg.General.ConfigDir)
	if err != nil {
		return err
	}
	staticInfo, err := beaconing.ParseStaticInfoCfg(cfg.General.StaticInfoConfig())
	if err != nil {
		log.Info("Failed to read static info", "err", err)
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

		OriginationInterval:  cfg.BS.OriginationInterval.Duration,
		PropagationInterval:  cfg.BS.PropagationInterval.Duration,
		RegistrationInterval: cfg.BS.RegistrationInterval.Duration,
		AllowIsdLoop:         isdLoopAllowed,
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

func setupBasic(file string) (config.Config, error) {
	var cfg config.Config
	if err := libconfig.LoadFile(file, &cfg); err != nil {
		return config.Config{}, serrors.WrapStr("loading config from file", err, "file", file)
	}
	cfg.InitDefaults()
	if err := log.Setup(cfg.Logging); err != nil {
		return config.Config{}, serrors.WrapStr("initialize logging", err)
	}
	prom.ExportElementID(cfg.General.ID)
	if err := env.LogAppStarted(common.CPService, cfg.General.ID); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func setup(cfg *config.Config) (*ifstate.Interfaces, error) {
	if err := cfg.Validate(); err != nil {
		return nil, serrors.WrapStr("validating config", err)
	}
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
