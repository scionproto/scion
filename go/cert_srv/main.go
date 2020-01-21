// Copyright 2017 ETH Zurich
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

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

var (
	cfg config.Config

	tasks *periodicTasks
)

func init() {
	flag.Usage = env.Usage
}

// main initializes the certificate server and starts the dispatcher.
func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(&cfg); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped(common.CS, cfg.General.ID)
	defer log.LogPanicAndExit()
	if err := setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		return 1
	}

	topo := itopo.Get()
	if !topo.Exists(addr.SvcCS, cfg.General.ID) {
		log.Crit("Unable to find topo address")
		return 1
	}
	tracer, trCloser, err := cfg.Tracing.NewTracer(cfg.General.ID)
	if err != nil {
		log.Crit("Unable to create tracer", "err", err)
		return 1
	}
	defer trCloser.Close()
	opentracing.SetGlobalTracer(tracer)

	router, err := infraenv.NewRouter(topo.IA(), cfg.Sciond)
	if err != nil {
		log.Crit("Unable to initialize path router", "err", err)
		return 1
	}

	nc := infraenv.NetworkConfig{
		IA:                    topo.IA(),
		Public:                topo.PublicAddress(addr.SvcCS, cfg.General.ID),
		SVC:                   addr.SvcCS,
		ReconnectToDispatcher: cfg.General.ReconnectToDispatcher,
		QUIC: infraenv.QUIC{
			Address:  cfg.QUIC.Address,
			CertFile: cfg.QUIC.CertFile,
			KeyFile:  cfg.QUIC.KeyFile,
		},
		SVCResolutionFraction: cfg.QUIC.ResolutionFraction,
		Router:                router,
		SVCRouter:             messenger.NewSVCRouter(itopo.Provider()),
	}
	msgr, err := nc.Messenger()
	if err != nil {
		log.Crit(infraenv.ErrAppUnableToInitMessenger.Error(), "err", err)
		return 1
	}
	defer msgr.CloseServer()

	trustDB, err := cfg.TrustDB.New()
	if err != nil {
		log.Crit("Error initializing trust database", "err", err)
		return 1
	}
	defer trustDB.Close()
	inserter := trust.DefaultInserter{
		BaseInserter: trust.BaseInserter{DB: trustDB},
	}
	provider := trust.Provider{
		DB:       trustDB,
		Recurser: trust.ASLocalRecurser{IA: topo.IA()},
		Resolver: trust.DefaultResolver{
			DB:       trustDB,
			Inserter: inserter,
			RPC:      trust.DefaultRPC{Msgr: msgr},
		},
		Router: trust.AuthRouter{
			ISD:    topo.IA().I,
			Router: router,
			DB:     trustDB,
		},
	}
	trustStore := trust.Store{
		Inspector:      trust.DefaultInspector{Provider: provider},
		CryptoProvider: provider,
		Inserter:       inserter,
		DB:             trustDB,
	}
	certsDir := filepath.Join(cfg.General.ConfigDir, "certs")
	if err = trustStore.LoadCryptoMaterial(context.Background(), certsDir); err != nil {
		log.Crit("Error loading crypto material", "err", err)
		return 1
	}
	gen := trust.SignerGen{
		IA: topo.IA(),
		KeyRing: keyconf.LoadingRing{
			Dir: filepath.Join(cfg.General.ConfigDir, "keys"),
			IA:  topo.IA(),
		},
		Provider: trustStore,
	}
	signer, err := gen.Signer(context.Background())
	if err != nil {
		log.Crit("Error initializing signer", "err", err)
		return 1
	}

	msgr.AddHandler(infra.ChainRequest, trustStore.NewChainReqHandler())
	msgr.AddHandler(infra.TRCRequest, trustStore.NewTRCReqHandler())
	msgr.AddHandler(infra.Chain, trustStore.NewChainPushHandler())
	msgr.AddHandler(infra.TRC, trustStore.NewTRCPushHandler())
	msgr.UpdateSigner(signer, []infra.MessageType{infra.ChainIssueRequest})
	msgr.UpdateVerifier(trust.NewVerifier(trustStore))

	// Setup metrics and status pages
	http.HandleFunc("/config", configHandler)
	http.HandleFunc("/info", env.InfoHandler)
	http.HandleFunc("/topology", itopo.TopologyHandler)
	cfg.Metrics.StartPrometheus()

	// Start the messenger.
	go func() {
		defer log.LogPanicAndExit()
		msgr.ListenAndServe()
	}()

	discoRunners, err := idiscovery.StartRunners(cfg.Discovery, discovery.Full,
		idiscovery.TopoHandlers{}, nil, "cs")
	if err != nil {
		log.Crit("Unable to start topology fetcher", "err", err)
		return 1
	}
	defer discoRunners.Kill()

	tasks = &periodicTasks{
		TopoProvider: itopo.Provider(),
		Msgr:         msgr,
		TrustDB:      trustDB,
	}
	if err := tasks.Start(); err != nil {
		log.Crit("Unable to start periodic tasks", "err", err)
		return 1
	}
	defer tasks.Kill()
	select {
	case <-fatal.ShutdownChan():
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		return 0
	case <-fatal.FatalChan():
		return 1
	}
}

type periodicTasks struct {
	TopoProvider topology.Provider
	Msgr         infra.Messenger
	TrustDB      trust.DB

	corePusher *periodic.Runner
	reissuance *periodic.Runner

	mtx     sync.Mutex
	running bool
}

func (t *periodicTasks) Start() error {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if t.running {
		log.Warn("Trying to start tasks, but they are running! Ignored.")
		return nil
	}
	t.running = true
	// t.corePusher = t.startCorePusher()
	// t.reissuance = t.startReissuance(t.corePusher)
	log.Info("Started periodic tasks")
	return nil
}

func (t *periodicTasks) Kill() {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if !t.running {
		log.Warn("Trying to stop tasks, but they are not running! Ignored.")
		return
	}
	t.reissuance.Kill()
	t.corePusher.Kill()
	t.nilTasks()
	t.running = false
	log.Info("Stopped periodic tasks.")
}

// nilTasks sets all tasks to nil. That is needed to rollback a partial start
// operation. If the Start operation fails a Kill call will nil all tasks using
// this method, which means after that we can call Start or Kill again without
// issues. This makes sure that we never call Kill on a task twice, since that
// would panic.
func (t *periodicTasks) nilTasks() {
	t.reissuance = nil
	t.corePusher = nil
}

func setupBasic() error {
	if _, err := toml.DecodeFile(env.ConfigFile(), &cfg); err != nil {
		return serrors.New("Failed to load config", "err", err, "file", env.ConfigFile())
	}
	cfg.InitDefaults()
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return serrors.New("Failed to initialize logging", "err", err)
	}
	prom.ExportElementID(cfg.General.ID)
	return env.LogAppStarted(common.CS, cfg.General.ID)
}

// setup initializes the config and sets the messenger.
func setup() error {
	if err := cfg.Validate(); err != nil {
		return serrors.WrapStr("unable to validate config", err)
	}
	itopo.Init(cfg.General.ID, proto.ServiceType_cs, itopo.Callbacks{})
	topo, err := topology.FromJSONFile(cfg.General.Topology)
	if err != nil {
		return serrors.WrapStr("unable to load topology", err)
	}
	if _, _, err := itopo.SetStatic(topo, false); err != nil {
		return serrors.WrapStr("Unable to set initial static topology", err)
	}
	infraenv.InitInfraEnvironment(cfg.General.Topology)
	return nil
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	var buf bytes.Buffer
	toml.NewEncoder(&buf).Encode(cfg)
	fmt.Fprint(w, buf.String())
}
