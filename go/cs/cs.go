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
	"fmt"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/cs/beaconstorage"
	"github.com/scionproto/scion/go/cs/config"
	"github.com/scionproto/scion/go/cs/handlers"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/keepalive"
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/cs/onehop"
	"github.com/scionproto/scion/go/cs/revocation"
	"github.com/scionproto/scion/go/cs/segreq"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	libconfig "github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/pkg/cs"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
	trusthandler "github.com/scionproto/scion/go/pkg/cs/trust/handler"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/compat"
	trustmetrics "github.com/scionproto/scion/go/pkg/trust/metrics"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
	"github.com/scionproto/scion/go/proto"
)

// CommandPather returns the path to a command.
type CommandPather interface {
	CommandPath() string
}

func main() {
	var flags struct {
		config string
	}
	cmd := &cobra.Command{
		Use:           "cs",
		Short:         "SCION Control Service instance",
		Example:       "  cs --config cs.toml",
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
	// TODO(roosd): This should be refactored when applying the new metrics
	// approach.
	metrics.InitBSMetrics()
	metrics.InitPSMetrics()
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

	nc := infraenv.NetworkConfig{
		IA:                    topo.IA(),
		Public:                topo.PublicAddress(addr.SvcBS, cfg.General.ID),
		SVC:                   addr.SvcWildcard,
		ReconnectToDispatcher: cfg.General.ReconnectToDispatcher,
		QUIC: infraenv.QUIC{
			Address:  cfg.QUIC.Address,
			CertFile: cfg.QUIC.CertFile,
			KeyFile:  cfg.QUIC.KeyFile,
		},
		SVCResolutionFraction: cfg.QUIC.ResolutionFraction,
		SVCRouter:             messenger.NewSVCRouter(itopo.Provider()),
		Version2:              cfg.Features.HeaderV2,
	}
	msgr, tcpMsgr, err := cs.NewMessenger(nc)
	if err != nil {
		return err
	}

	pathDB, revCache, err := pathstorage.NewPathStorage(cfg.PathDB)
	if err != nil {
		return serrors.WrapStr("initializing path storage", err)
	}
	defer revCache.Close()
	pathDB = pathdb.WithMetrics(string(cfg.PathDB.Backend()), pathDB)
	defer pathDB.Close()

	trustDB, err := cfg.TrustDB.New()
	if err != nil {
		return serrors.WrapStr("initializing trust storage", err)
	}
	trustDB = trustmetrics.WrapDB(string(cfg.TrustDB.Backend()), trustDB)
	defer trustDB.Close()
	if err := cs.LoadTrustMaterial(cfg.General.ConfigDir, trustDB, log.Root()); err != nil {
		return err
	}

	beaconStore, isdLoopAllowed, err := loadBeaconStore(topo.Core(), topo.IA(), cfg)
	if err != nil {
		return serrors.WrapStr("initializing beacon store", err)
	}
	defer beaconStore.Close()

	inspector := trust.DBInspector{DB: trustDB}
	provider := cs.NewTrustProvider(
		cs.TrustProviderConfig{
			IA:       topo.IA(),
			TrustDB:  trustDB,
			RPC:      msgr,
			HeaderV2: cfg.Features.HeaderV2,
		},
	)
	verifier := compat.Verifier{
		Verifier: trust.Verifier{
			Engine: provider,
		},
	}
	fetcherCfg := segreq.FetcherConfig{
		IA:           topo.IA(),
		PathDB:       pathDB,
		RevCache:     revCache,
		RequestAPI:   msgr,
		Inspector:    inspector,
		TopoProvider: itopo.Provider(),
		Verifier:     verifier,
		HeaderV2:     cfg.Features.HeaderV2,
	}
	cs.SetTrustRouter(&provider, segreq.NewRouter(fetcherCfg))

	// Register trust material related handlers.
	trcHandler := trusthandler.TRCReq{Provider: provider, IA: topo.IA()}
	cs.MultiRegister(infra.TRCRequest, trcHandler, msgr, tcpMsgr)
	chainHandler := trusthandler.ChainReq{Provider: provider, IA: topo.IA()}
	cs.MultiRegister(infra.ChainRequest, chainHandler, msgr, tcpMsgr)

	// Register pathing related handlers
	msgr.AddHandler(infra.Seg, beaconing.NewHandler(topo.IA(), intfs, beaconStore, verifier))

	tcpMsgr.AddHandler(infra.SegRequest, segreq.NewForwardingHandler(
		topo.IA(),
		topo.Core(),
		inspector,
		pathDB,
		revCache,
		segreq.NewFetcher(fetcherCfg),
	))

	if topo.Core() {
		msgr.AddHandler(infra.SegRequest, segreq.NewAuthoritativeHandler(
			topo.IA(),
			inspector,
			pathDB,
			revCache,
		))

		segHandler := seghandler.Handler{
			Verifier: &seghandler.DefaultVerifier{
				Verifier: verifier,
			},
			Storage: &seghandler.DefaultStorage{
				PathDB:   pathDB,
				RevCache: revCache,
			},
		}
		msgr.AddHandler(infra.SegReg, &handlers.SegReg{SegHandler: segHandler})
	}

	// Keepalive mechanism is deprecated and will be removed with change to
	// header v2. Disable with https://github.com/Anapaya/scion/issues/3337.
	if !cfg.Features.HeaderV2 || true {
		msgr.AddHandler(infra.IfStateReq, ifstate.NewHandler(intfs))
		msgr.AddHandler(infra.IfId, keepalive.NewHandler(topo.IA(), intfs,
			keepalive.StateChangeTasks{
				RevDropper: beaconStore,
				IfStatePusher: ifstate.PusherConf{
					Intfs:        intfs,
					Msgr:         msgr,
					TopoProvider: itopo.Provider(),
				}.New(),
			}),
		)
	}
	revHandler := handlers.RevocHandler{
		RevCache: revCache,
		Verifier: verifier,
	}
	otherRevHandler := revocation.NewHandler(beaconStore, verifier, 5*time.Second)
	msgr.AddHandler(infra.SignedRev, infra.HandlerFunc(func(r *infra.Request) *infra.HandlerResult {
		revHandler.Handle(r)
		otherRevHandler.Handle(r)
		// Always return success, since the metrics libraries ignore this result anyway
		return &infra.HandlerResult{
			Result: prom.Success,
			Status: prom.StatusOk,
		}
	}))

	signer, err := cs.NewSigner(topo.IA(), trustDB, cfg.General.ConfigDir)
	if err != nil {
		return serrors.WrapStr("initializing AS signer", err)
	}

	var chainBuilder cstrust.ChainBuilder
	if topo.CA() {
		renewalDB, err := cfg.RenewalDB.New()
		if err != nil {
			return serrors.WrapStr("initializing renewal database", err)
		}
		defer renewalDB.Close()
		if err := cs.LoadClientChains(renewalDB, cfg.General.ConfigDir); err != nil {
			return serrors.WrapStr("loading client certificate chains", err)
		}
		chainBuilder = cs.NewChainBuilder(topo.IA(), trustDB, cfg.CA.MaxASValidity.Duration,
			cfg.General.ConfigDir)
		cs.MultiRegister(infra.ChainRenewalRequest,
			trusthandler.ChainRenewalRequest{
				Verifier: trusthandler.RenewalRequestVerifierFunc(
					renewal.VerifyChainRenewalRequest),
				ChainBuilder: chainBuilder,
				DB:           renewalDB,
				IA:           topo.IA(),
				Signer:       signer,
			},
			msgr, tcpMsgr,
		)
	}

	go func() {
		defer log.HandlePanic()
		msgr.ListenAndServe()
	}()
	defer msgr.CloseServer()
	go func() {
		defer log.HandlePanic()
		tcpMsgr.ListenAndServe()
	}()
	defer tcpMsgr.CloseServer()
	cs.StartHTTPEndpoints(cfg, signer, chainBuilder, cfg.Metrics)

	ohpConn, err := cs.NewOneHopConn(topo.IA(), nc.Public, "", cfg.General.ReconnectToDispatcher,
		cfg.Features.HeaderV2)
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
	tasks, err := cs.StartTasks(cs.TasksConfig{
		Public:      nc.Public,
		Intfs:       intfs,
		TrustDB:     trustDB,
		PathDB:      pathDB,
		RevCache:    revCache,
		BeaconStore: beaconStore,
		Signer:      signer,
		OneHopConn:  ohpConn,
		Msgr:        msgr,
		AddressRewriter: nc.AddressRewriter(
			&onehop.OHPPacketDispatcherService{
				PacketDispatcherService: &snet.DefaultPacketDispatcherService{
					Dispatcher: reliable.NewDispatcher(""),
					Version2:   cfg.Features.HeaderV2,
				},
			},
		),
		Inspector:    inspector,
		MACGen:       macGen,
		TopoProvider: itopo.Provider(),
		StaticInfo:   func() *beaconing.StaticInfoCfg { return staticInfo },

		OriginationInterval:  cfg.BS.OriginationInterval.Duration,
		PropagationInterval:  cfg.BS.PropagationInterval.Duration,
		RegistrationInterval: cfg.BS.RegistrationInterval.Duration,
		AllowIsdLoop:         isdLoopAllowed,
		HeaderV2:             cfg.Features.HeaderV2,
	})
	if err != nil {
		serrors.WrapStr("starting periodic tasks", err)
	}
	defer tasks.Kill()
	log.Info("Started periodic tasks")

	// Disable when addressing https://github.com/Anapaya/scion/issues/3337.
	if !cfg.Features.HeaderV2 || true {
		legacy := cs.StartLegacyTasks(cs.LegacyTasksConfig{
			Public:               nc.Public,
			Intfs:                intfs,
			OneHopConn:           ohpConn,
			BeaconStore:          beaconStore,
			Signer:               signer,
			Msgr:                 msgr,
			MACGen:               macGen,
			TopoProvider:         itopo.Provider(),
			KeepaliveInterval:    cfg.BS.KeepaliveInterval.Duration,
			ExpiredCheckInterval: cfg.BS.ExpiredCheckInterval.Duration,
			RevTTL:               cfg.BS.RevTTL.Duration,
			RevOverlap:           cfg.BS.RevOverlap.Duration,
			HeaderV2:             cfg.Features.HeaderV2,
		})
		defer legacy.Kill()
	}
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
	prometheus.MustRegister(ifstate.NewCollector(intfs))
	itopo.Init(&itopo.Config{
		ID:  cfg.General.ID,
		Svc: proto.ServiceType_cs,
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

func loadBeaconStore(core bool, ia addr.IA, cfg config.Config) (beaconstorage.Store, bool, error) {
	if core {
		policies, err := cs.LoadCorePolicies(cfg.BS.Policies)
		if err != nil {
			return nil, false, err
		}
		store, err := cfg.BeaconDB.NewCoreStore(ia, policies)
		return store, *policies.Prop.Filter.AllowIsdLoop, err
	}
	policies, err := cs.LoadNonCorePolicies(cfg.BS.Policies)
	if err != nil {
		return nil, false, err
	}
	store, err := cfg.BeaconDB.NewStore(ia, policies)
	return store, *policies.Prop.Filter.AllowIsdLoop, err
}
