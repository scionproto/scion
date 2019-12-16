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
	"context"
	"flag"
	"fmt"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/cert_srv/internal/reiss"
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
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
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
	// Setup the state and the messenger
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
	trustDB, err := cfg.TrustDB.New()
	if err != nil {
		log.Crit("Unable to initialize trustDB", "err", err)
		return 1
	}
	trustDB = trustdb.WithMetrics(string(cfg.TrustDB.Backend()), trustDB)
	defer trustDB.Close()
	trustConf := trust.Config{
		MustHaveLocalChain: true,
		ServiceType:        proto.ServiceType_cs,
		Router:             router,
		TopoProvider:       itopo.Provider(),
	}
	trustStore := trust.NewStore(trustDB, topo.IA(), trustConf, log.Root())
	err = trustStore.LoadAuthoritativeCrypto(filepath.Join(cfg.General.ConfigDir, "certs"))
	if err != nil {
		log.Crit("Unable to load local crypto", "err", err)
		return 1
	}

	state, err := newState(topo, trustDB, trustStore)
	if err != nil {
		log.Crit("Unable to load state", "err", err)
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
		TrustStore:            trustStore,
		Router:                router,
		SVCRouter:             messenger.NewSVCRouter(itopo.Provider()),
	}
	msgr, err := nc.Messenger()
	if err != nil {
		log.Crit(infraenv.ErrAppUnableToInitMessenger.Error(), "err", err)
		return 1
	}
	defer msgr.CloseServer()

	msgr.AddHandler(infra.ChainRequest, trustStore.NewChainReqHandler(true))
	msgr.AddHandler(infra.TRCRequest, trustStore.NewTRCReqHandler(true))
	msgr.AddHandler(infra.Chain, trustStore.NewChainPushHandler())
	msgr.AddHandler(infra.TRC, trustStore.NewTRCPushHandler())
	msgr.UpdateSigner(state.GetSigner(), []infra.MessageType{infra.ChainIssueRequest})
	msgr.UpdateVerifier(trust.NewBasicVerifier(trustStore))
	// Only core CS handles certificate reissuance requests.
	if topo.Core() {
		msgr.AddHandler(infra.ChainIssueRequest, &reiss.Handler{
			State: state,
			IA:    topo.IA(),
		})
	}

	go func() {
		defer log.LogPanicAndExit()
		msgr.ListenAndServe()
	}()
	cfg.Metrics.StartPrometheus()

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
		State:        state,
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
	TrustDB      trustdb.TrustDB
	State        *config.State

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
	t.corePusher = t.startCorePusher()
	t.reissuance = t.startReissuance(t.corePusher)
	log.Info("Started periodic tasks")
	return nil
}

func (t *periodicTasks) startCorePusher() *periodic.Runner {
	if cfg.CS.DisableCorePush {
		return nil
	}
	p := periodic.Start(
		&reiss.CorePusher{
			LocalIA: t.TopoProvider.Get().IA(),
			TrustDB: t.TrustDB,
			Msger:   t.Msgr,
		},
		time.Hour,
		time.Minute,
	)
	p.TriggerRun()
	return p
}

func (t *periodicTasks) startReissuance(corePusher *periodic.Runner) *periodic.Runner {
	if !cfg.CS.AutomaticRenewal {
		log.Info("Certificate reissuance disabled, not starting periodic task.")
		return nil
	}
	if t.TopoProvider.Get().Core() {
		log.Info("Starting periodic self-issuing reissuance task.")
		return periodic.Start(
			&reiss.Self{
				Msgr:       t.Msgr,
				State:      t.State,
				IA:         t.TopoProvider.Get().IA(),
				IssTime:    cfg.CS.IssuerReissueLeadTime.Duration,
				LeafTime:   cfg.CS.LeafReissueLeadTime.Duration,
				CorePusher: corePusher,
				Caller:     "cs",
			},
			cfg.CS.ReissueRate.Duration,
			cfg.CS.ReissueTimeout.Duration,
		)
	}
	log.Info("Starting periodic reissuance requester task.")
	return periodic.Start(
		&reiss.Requester{
			Msgr:       t.Msgr,
			State:      t.State,
			IA:         t.TopoProvider.Get().IA(),
			LeafTime:   cfg.CS.LeafReissueLeadTime.Duration,
			CorePusher: corePusher,
		},
		cfg.CS.ReissueRate.Duration,
		cfg.CS.ReissueTimeout.Duration,
	)
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
		return err
	}
	cfg.InitDefaults()
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return err
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

// TODO(roosd): Remove with trust store v2
func newState(topo topology.Topology, db trustdb.TrustDB,
	store *trust.Store) (*config.State, error) {

	state, err := config.LoadState(cfg.General.ConfigDir, topo.Core(), db, store)
	if err != nil {
		return nil, serrors.WrapStr("unable to load CS state", err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()
	meta, err := trust.CreateSignMeta(ctx, topo.IA(), db)
	if err != nil {
		return nil, err
	}
	signer, err := trust.NewBasicSigner(state.GetSigningKey(), meta)
	if err != nil {
		return nil, err
	}
	state.SetSigner(signer)
	state.SetVerifier(state.Store.NewVerifier())
	return state, nil
}
