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

// Package cs implements the SCION Control Service.
package cs

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/pelletier/go-toml"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing"
	beaconingcompat "github.com/scionproto/scion/go/cs/beaconing/compat"
	"github.com/scionproto/scion/go/cs/beaconstorage"
	"github.com/scionproto/scion/go/cs/config"
	"github.com/scionproto/scion/go/cs/handlers"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/keepalive"
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/cs/onehop"
	"github.com/scionproto/scion/go/cs/revocation"
	"github.com/scionproto/scion/go/cs/segreq"
	"github.com/scionproto/scion/go/cs/segsyncer"
	"github.com/scionproto/scion/go/cs/segutil"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	libconfig "github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/messenger/tcp"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
	trusthandler "github.com/scionproto/scion/go/pkg/cs/trust/handler"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/compat"
	trustmetrics "github.com/scionproto/scion/go/pkg/trust/metrics"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
	"github.com/scionproto/scion/go/proto"
)

var (
	Cfg config.Config

	staticInfoCfg *beaconing.StaticInfoCfg

	Intfs *ifstate.Interfaces
	Tasks *PeriodicTasks

	HelpPolicy bool
)

func init() {
	flag.Usage = env.Usage
}

// App exposes configuration hooks for Control Service internals.
type App struct {
	ConfigLoader        func() error
	PathDB              func(path pathstorage.PathDBConf) (pathdb.PathDB, revcache.RevCache, error)
	TrustDB             func() (trust.DB, error)
	RenewalDB           func() (renewal.DB, error)
	BeaconStore         func(core bool, ia addr.IA, cfg config.Config) (beaconstorage.Store, error)
	HandlerWrapper      func(msgType infra.MessageType, h infra.Handler) infra.Handler
	Tasks               func() (func(), error)
	TopologyFactory     func(*topology.RWTopology) topology.Topology
	TopologyInitializer func(topo topology.Topology) error
}

func (app *App) runConfigLoader() error {
	if app.ConfigLoader != nil {
		return app.ConfigLoader()
	}
	return libconfig.LoadFile(env.ConfigFile(), &Cfg)
}

func (app *App) runPathDBConstructor(
	path pathstorage.PathDBConf) (pathdb.PathDB, revcache.RevCache, error) {

	if app.PathDB != nil {
		return app.PathDB(path)
	}
	return pathstorage.NewPathStorage(Cfg.PathDB)
}

func (app *App) runTrustDBConstructor() (trust.DB, error) {
	if app.TrustDB != nil {
		return app.TrustDB()
	}
	return Cfg.TrustDB.New()
}

func (app *App) runRenewalDBConstructor() (renewal.DB, error) {
	if app.RenewalDB != nil {
		return app.RenewalDB()
	}
	return Cfg.RenewalDB.New()
}

func (app *App) runBeaconStoreConstructor(
	core bool, ia addr.IA, cfg config.Config) (beaconstorage.Store, error) {

	if app.BeaconStore != nil {
		return app.BeaconStore(core, ia, cfg)
	}
	return loadStore(core, ia, cfg)
}

func (app *App) runHandlerWrapper(msgType infra.MessageType, h infra.Handler) infra.Handler {
	if app.HandlerWrapper != nil {
		return app.HandlerWrapper(msgType, h)
	}
	return h
}

func (app *App) runTaskConstructor() (func(), error) {
	if app.Tasks != nil {
		return app.Tasks()
	}
	if err := Tasks.Start(); err != nil {
		return nil, serrors.WrapStr("unable to start tasks", err)
	}
	return Tasks.Kill, nil
}

func (app *App) runTopologyInitializer(topo topology.Topology) error {
	if app.TopologyInitializer != nil {
		return app.TopologyInitializer(topo)
	}
	return initTopo(topo)
}

// InitLogging sets up the application's logging system.
func InitLogging() error {
	if err := log.Setup(Cfg.Logging); err != nil {
		return serrors.WrapStr("failed to initialize logging", err)
	}
	prom.ExportElementID(Cfg.General.ID)
	return env.LogAppStarted(common.CS, Cfg.General.ID)
}

func (app *App) Run() int {
	defer env.LogAppStopped(common.CPService, Cfg.General.ID)
	defer log.HandlePanic()
	if err := app.setup(); err != nil {
		log.Error("Setup failed", "err", err)
		return 1
	}
	metrics.InitBSMetrics()
	metrics.InitPSMetrics()

	pathDB, revCache, err := app.runPathDBConstructor(Cfg.PathDB)
	if err != nil {
		log.Error("Path storage initialization failed", "err", err)
		return 1
	}
	defer revCache.Close()
	pathDB = pathdb.WithMetrics(string(Cfg.PathDB.Backend()), pathDB)
	defer pathDB.Close()

	topo := itopo.Get()
	// Check that this process ID is present.
	if !topo.Exists(addr.SvcCS, Cfg.General.ID) {
		log.Error("CS ID not found in topology file", "id", Cfg.General.ID)
		return 1
	}

	tracer, trCloser, err := Cfg.Tracing.NewTracer(Cfg.General.ID)
	if err != nil {
		log.Error("Tracer initialization failed", "err", err)
		return 1
	}
	defer trCloser.Close()
	opentracing.SetGlobalTracer(tracer)

	nc := infraenv.NetworkConfig{
		IA: topo.IA(),
		// Inherit addresses from BS; they should all match though
		// TODO(scrye): add check for addresses
		Public:                topo.PublicAddress(addr.SvcBS, Cfg.General.ID),
		SVC:                   addr.SvcWildcard,
		ReconnectToDispatcher: Cfg.General.ReconnectToDispatcher,
		QUIC: infraenv.QUIC{
			Address:  Cfg.QUIC.Address,
			CertFile: Cfg.QUIC.CertFile,
			KeyFile:  Cfg.QUIC.KeyFile,
		},
		SVCResolutionFraction: Cfg.QUIC.ResolutionFraction,
		SVCRouter:             messenger.NewSVCRouter(itopo.Provider()),
		Version2:              Cfg.Features.HeaderV2,
	}
	msgr, err := nc.Messenger()
	if err != nil {
		log.Error(infraenv.ErrAppUnableToInitMessenger.Error(), "err", err)
		return 1
	}

	tcpMsgr := tcp.NewServerMessenger(&net.TCPAddr{
		IP:   nc.Public.IP,
		Port: nc.Public.Port,
		Zone: nc.Public.Zone,
	})

	trustDB, err := app.runTrustDBConstructor()
	if err != nil {
		log.Error("Trust database initialization failed", "err", err)
		return 1
	}
	trustDB = trustmetrics.WrapDB(string(Cfg.TrustDB.Backend()), trustDB)
	defer trustDB.Close()

	certsDir := filepath.Join(Cfg.General.ConfigDir, "certs")
	loaded, err := trust.LoadTRCs(context.Background(), certsDir, trustDB)
	if err != nil {
		log.Error("Loading TRCs from disk failed", "err", err)
		return 1
	}
	log.Info("TRCs loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		log.Info("Ignoring non-TRC", "file", f, "reason", r)
	}

	localCertsDir := filepath.Join(Cfg.General.ConfigDir, "crypto/as")
	loaded, err = trust.LoadChains(context.Background(), localCertsDir, trustDB)
	if err != nil {
		log.Error("Loading certificate chains from disk failed", "err", err)
		return 1
	}
	log.Info("Certificate chains loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		log.Info("Ignoring non-certificate chain", "file", f, "reason", r)
	}

	trustRouter := &segutil.Router{
		Pather: segfetcher.Pather{
			PathDB:       pathDB,
			RevCache:     revCache,
			TopoProvider: itopo.Provider(),
			// Fetcher needs to be initialized with a provider.
		},
	}
	provider := trust.FetchingProvider{
		DB: trustDB,
		Fetcher: trust.DefaultFetcher{
			RPC: msgr,
			IA:  topo.IA(),
		},
		Recurser: trust.ASLocalRecurser{IA: topo.IA()},
		Router: trust.AuthRouter{
			ISD:    topo.IA().I,
			DB:     trustDB,
			Router: trustRouter,
		},
	}
	inspector := trust.DBInspector{DB: trustDB}

	args := handlers.HandlerArgs{
		PathDB:        pathDB,
		RevCache:      revCache,
		ASInspector:   inspector,
		Verifier:      compat.Verifier{Verifier: trust.Verifier{Engine: provider}},
		QueryInterval: Cfg.PS.QueryInterval.Duration,
		IA:            topo.IA(),
		TopoProvider:  itopo.Provider(),
		SegRequestAPI: msgr,
	}

	trustRouter.Pather.Fetcher = segfetcher.FetcherConfig{
		QueryInterval: Cfg.PS.QueryInterval.Duration,
		LocalIA:       topo.IA(),
		Verifier:      compat.Verifier{Verifier: trust.Verifier{Engine: provider}},
		PathDB:        pathDB,
		RevCache:      revCache,
		RequestAPI:    msgr,
		DstProvider:   segreq.CreateDstProvider(args, topo.Core()),
		Splitter: &segfetcher.MultiSegmentSplitter{
			Local:     topo.IA(),
			Inspector: inspector,
		},
		MetricsNamespace: metrics.PSNamespace,
		LocalInfo:        segreq.CreateLocalInfo(args, topo.Core()),
	}.New()

	beaconStore, err := app.runBeaconStoreConstructor(topo.Core(), topo.IA(), Cfg)
	if err != nil {
		log.Error("Beacon store initialization failed", "err", err)
		return 1
	}
	defer beaconStore.Close()
	Intfs = ifstate.NewInterfaces(topo.IFInfoMap(), ifstate.Config{})
	prometheus.MustRegister(ifstate.NewCollector(Intfs))

	trcReqHandler := trusthandler.TRCReq{Provider: provider, IA: topo.IA()}
	chainReqHandler := trusthandler.ChainReq{Provider: provider, IA: topo.IA()}
	segReqHandler := segreq.NewHandler(args)

	msgr.AddHandler(infra.TRCRequest,
		app.runHandlerWrapper(infra.TRCRequest, trcReqHandler))
	msgr.AddHandler(infra.ChainRequest,
		app.runHandlerWrapper(infra.ChainRequest, chainReqHandler))
	msgr.AddHandler(infra.IfStateReq,
		app.runHandlerWrapper(infra.IfStateReq, ifstate.NewHandler(Intfs)))
	msgr.AddHandler(infra.Seg,
		app.runHandlerWrapper(infra.Seg, beaconing.NewHandler(topo.IA(), Intfs, beaconStore,
			compat.Verifier{Verifier: trust.Verifier{Engine: provider}})))
	msgr.AddHandler(infra.IfId,
		app.runHandlerWrapper(infra.IfId, keepalive.NewHandler(topo.IA(), Intfs,
			keepalive.StateChangeTasks{
				RevDropper: beaconStore,
				IfStatePusher: ifstate.PusherConf{
					Intfs:        Intfs,
					Msgr:         msgr,
					TopoProvider: itopo.Provider(),
				}.New(),
			}),
		),
	)
	msgr.AddHandler(infra.SegRequest, app.runHandlerWrapper(infra.SegRequest, segReqHandler))
	msgr.AddHandler(infra.SegReg,
		app.runHandlerWrapper(infra.SegReg, handlers.NewSegRegHandler(args)))
	if topo.Core() {
		// Old down segment sync mechanism
		msgr.AddHandler(infra.SegSync,
			app.runHandlerWrapper(infra.SegSync, handlers.NewSyncHandler(args)))
	}
	msgr.AddHandler(infra.SignedRev, app.runHandlerWrapper(infra.SignedRev, &chainedHandler{
		handlers: []infra.Handler{
			handlers.NewRevocHandler(args),
			revocation.NewHandler(
				beaconStore,
				compat.Verifier{Verifier: trust.Verifier{Engine: provider}},
				5*time.Second),
		},
	}))

	tcpMsgr.AddHandler(infra.TRCRequest,
		app.runHandlerWrapper(infra.TRCRequest, trcReqHandler))
	tcpMsgr.AddHandler(infra.ChainRequest,
		app.runHandlerWrapper(infra.ChainRequest, chainReqHandler))
	tcpMsgr.AddHandler(infra.SegRequest, app.runHandlerWrapper(infra.SegRequest, segReqHandler))

	signer, err := createSigner(topo.IA(), trustDB)
	if err != nil {
		log.Error("Signer initialization failed", "err", err)
		return 1
	}
	if topo.CA() {
		renewalDB, err := app.runRenewalDBConstructor()
		if err != nil {
			log.Error("Renewal database initialization failed", "err", err)
			return 1
		}
		defer renewalDB.Close()
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		err = cstrust.ClientLoader{
			Dir:      filepath.Join(Cfg.General.ConfigDir, "crypto/ca/clients"),
			ClientDB: renewalDB,
		}.LoadClientChains(ctx)
		if err != nil {
			log.Error("Loading client certificate chains failed", "err", err)
			return 1
		}
		renewalHandler := trusthandler.ChainRenewalRequest{
			Verifier: trusthandler.RenewalRequestVerifierFunc(
				renewal.VerifyChainRenewalRequest),
			ChainBuilder: cstrust.ChainBuilder{
				PolicyGen: &cstrust.CachingPolicyGen{
					PolicyGen: cstrust.LoadingPolicyGen{
						Validity: 3 * 24 * time.Hour,
						CertProvider: cstrust.CACertLoader{
							IA:  topo.IA(),
							DB:  trustDB,
							Dir: filepath.Join(Cfg.General.ConfigDir, "crypto/ca"),
						},
						KeyRing: cstrust.LoadingRing{
							Dir: filepath.Join(Cfg.General.ConfigDir, "crypto/ca"),
						},
					},
				},
			},
			DB:     renewalDB,
			IA:     topo.IA(),
			Signer: signer,
		}

		msgr.AddHandler(infra.ChainRenewalRequest,
			app.runHandlerWrapper(infra.ChainRenewalRequest, renewalHandler))
		tcpMsgr.AddHandler(infra.ChainRenewalRequest,
			app.runHandlerWrapper(infra.ChainRenewalRequest, renewalHandler))

	}

	// Setup metrics and status pages
	http.HandleFunc("/config", configHandler)
	http.HandleFunc("/info", env.InfoHandler)
	http.HandleFunc("/topology", itopo.TopologyHandler)
	http.HandleFunc("/signer", signerHandler(signer))
	Cfg.Metrics.StartPrometheus()
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

	dispatcherService := reliable.NewDispatcher("")
	if Cfg.General.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}
	pktDisp := &snet.DefaultPacketDispatcherService{
		Dispatcher: dispatcherService,
		Version2:   Cfg.Features.HeaderV2,
	}
	// We do not need to drain the connection, since the src address is spoofed
	// to contain the topo address.
	ohpAddress := snet.CopyUDPAddr(topo.PublicAddress(addr.SvcBS, Cfg.General.ID))
	ohpAddress.Port = 0
	conn, _, err := pktDisp.Register(context.Background(), topo.IA(), ohpAddress, addr.SvcNone)
	if err != nil {
		log.Error("SCION packet conn initialization failed", "err", err)
		return 1
	}
	propPolicy, err := loadPolicy(Cfg.BS.Policies.Propagation, beacon.PropPolicy)
	if err != nil {
		log.Error("Loading propagation policy failed", "err", err)
		return 1
	}
	Tasks = &PeriodicTasks{
		headerV2:     Cfg.Features.HeaderV2,
		args:         args,
		intfs:        Intfs,
		conn:         conn.(*snet.SCIONPacketConn),
		trustDB:      trustDB,
		signer:       signer,
		store:        beaconStore,
		allowIsdLoop: *propPolicy.Filter.AllowIsdLoop,
		pathDB:       pathDB,
		msgr:         msgr,
		TopoProvider: itopo.Provider(),
		addressRewriter: nc.AddressRewriter(
			&onehop.OHPPacketDispatcherService{
				PacketDispatcherService: &snet.DefaultPacketDispatcherService{
					Dispatcher: reliable.NewDispatcher(""),
					Version2:   Cfg.Features.HeaderV2,
				},
			},
		),
	}
	msgr.UpdateSigner(signer, []infra.MessageType{infra.Seg, infra.ChainRenewalRequest})
	// TODO(scrye): this breaks Interface Keepalives if it is enabled
	// msgr.UpdateVerifier(trust.NewVerifier(trustStore))

	if Tasks.genMac, err = macGenFactory(); err != nil {
		log.Error("MAC generator initialization failed", "err", err)
		return 1
	}

	cleanupF, err := app.runTaskConstructor()
	if err != nil {
		log.Error("Run task hooks failed", "err", err)
		return 1
	}
	defer cleanupF()

	select {
	case <-fatal.ShutdownChan():
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		return 0
	case <-fatal.FatalChan():
		return 1
	}
}

type segRegRunners struct {
	coreRegistrar *periodic.Runner
	upRegistrar   *periodic.Runner
	downRegistrar *periodic.Runner
	core          bool
}

func (s segRegRunners) Kill() {
	s.coreRegistrar.Kill()
	s.upRegistrar.Kill()
	s.downRegistrar.Kill()
}

type PeriodicTasks struct {
	args            handlers.HandlerArgs
	intfs           *ifstate.Interfaces
	conn            *snet.SCIONPacketConn
	genMac          func() hash.Hash
	trustDB         trust.DB
	signer          ctrl.Signer
	store           beaconstorage.Store
	pathDB          pathdb.PathDB
	msgr            infra.Messenger
	TopoProvider    topology.Provider
	allowIsdLoop    bool
	addressRewriter *messenger.AddressRewriter
	headerV2        bool

	Keepalive  *periodic.Runner
	originator *periodic.Runner
	propagator *periodic.Runner
	revoker    *periodic.Runner
	registrars segRegRunners

	corePusher *periodic.Runner
	reissuance *periodic.Runner

	beaconCleaner *periodic.Runner
	revCleaner    *periodic.Runner

	segSyncers    []*periodic.Runner
	pathDBCleaner *periodic.Runner
	cryptosyncer  *periodic.Runner
	rcCleaner     *periodic.Runner

	Mtx     sync.Mutex
	Running bool
}

// nilTasks sets all tasks to nil. That is needed to rollback a partial start
// operation. If the Start operation fails a Kill call will nil all tasks using
// this method, which means after that we can call Start or Kill again without
// issues. This makes sure that we never call Kill on a task twice, since that
// would panic.
func (t *PeriodicTasks) nilTasks() {
	t.registrars.upRegistrar = nil
	t.registrars.coreRegistrar = nil
	t.registrars.downRegistrar = nil
	t.revoker = nil
	t.Keepalive = nil
	t.originator = nil
	t.propagator = nil
	t.beaconCleaner = nil
	t.revCleaner = nil
	t.reissuance = nil
	t.corePusher = nil
	t.segSyncers = nil
	t.pathDBCleaner = nil
	t.cryptosyncer = nil
	t.rcCleaner = nil
}

func (t *PeriodicTasks) Start() error {
	t.Mtx.Lock()
	defer t.Mtx.Unlock()
	if t.Running {
		log.Info("Trying to start tasks, but they are running! Ignored.")
		return nil
	}
	t.Running = true
	topo := t.TopoProvider.Get()
	bs := topo.PublicAddress(addr.SvcBS, Cfg.General.ID)
	if bs == nil {
		return serrors.New("Unable to find topo address")
	}

	var err error
	if t.registrars, err = t.startSegRegRunners(); err != nil {
		return err
	}
	if t.revoker, err = t.startRevoker(); err != nil {
		return err
	}
	if t.Keepalive, err = t.StartKeepaliveSender(bs); err != nil {
		return err
	}
	if t.originator, err = t.startOriginator(bs); err != nil {
		return err
	}
	if t.propagator, err = t.startPropagator(bs); err != nil {
		return err
	}

	t.beaconCleaner = periodic.Start(
		beaconstorage.NewBeaconCleaner(t.store),
		30*time.Second, 30*time.Second)
	t.revCleaner = periodic.Start(
		beaconstorage.NewRevocationCleaner(t.store), 5*time.Second, 5*time.Second)

	// t.corePusher = t.startCorePusher()
	// t.reissuance = t.startReissuance(t.corePusher)

	if itopo.Get().Core() {
		t.segSyncers, err = segsyncer.StartAll(t.args, t.msgr)
		if err != nil {
			return common.NewBasicError("Unable to start seg syncer", err)
		}
	}
	t.pathDBCleaner = periodic.Start(pathdb.NewCleaner(t.args.PathDB, "ps_segments"),
		300*time.Second, 295*time.Second)
	// TODO(roosd): Re-enable
	// t.cryptosyncer = periodic.Start(&cryptosyncer.Syncer{
	// 	DB:    t.trustDB,
	// 	Msger: t.msger,
	// 	IA:    t.args.IA,
	// }, cfg.PS.CryptoSyncInterval.Duration, cfg.PS.CryptoSyncInterval.Duration)
	t.rcCleaner = periodic.Start(revcache.NewCleaner(t.args.RevCache, "ps_revocation"),
		10*time.Second, 10*time.Second)

	log.Info("Started periodic tasks")
	return nil
}

func (t *PeriodicTasks) startRevoker() (*periodic.Runner, error) {
	r := ifstate.RevokerConf{
		Intfs:        t.intfs,
		Msgr:         t.msgr,
		RevInserter:  t.store,
		Signer:       t.signer,
		TopoProvider: t.TopoProvider,
		RevConfig: ifstate.RevConfig{
			RevTTL:     Cfg.BS.RevTTL.Duration,
			RevOverlap: Cfg.BS.RevOverlap.Duration,
		},
	}.New()
	return periodic.Start(r, Cfg.BS.ExpiredCheckInterval.Duration,
		Cfg.BS.ExpiredCheckInterval.Duration), nil
}

func (t *PeriodicTasks) StartKeepaliveSender(a *net.UDPAddr) (*periodic.Runner, error) {
	s := &keepalive.Sender{
		Sender: &onehop.Sender{
			Conn: t.conn,
			IA:   t.TopoProvider.Get().IA(),
			MAC:  t.genMac(),
			Addr: a,
		},
		Signer:       infra.NullSigner,
		TopoProvider: t.TopoProvider,
	}
	return periodic.Start(s, Cfg.BS.KeepaliveInterval.Duration,
		Cfg.BS.KeepaliveInterval.Duration), nil
}

func (t *PeriodicTasks) startOriginator(a *net.UDPAddr) (*periodic.Runner, error) {
	topo := t.TopoProvider.Get()
	if !topo.Core() {
		return nil, nil
	}
	s := &beaconing.Originator{
		Extender: t.extender("propagator", topo, maxExpTimeFactory(t.store, beacon.PropPolicy)),
		BeaconSender: &onehop.BeaconSender{
			Sender: onehop.Sender{
				Conn: t.conn,
				IA:   topo.IA(),
				MAC:  t.genMac(),
				Addr: a,
			},
			AddressRewriter:  t.addressRewriter,
			QUICBeaconSender: t.msgr,
		},
		IA:     topo.IA(),
		Intfs:  t.intfs,
		Signer: t.signer,
		Tick:   beaconing.NewTick(Cfg.BS.OriginationInterval.Duration),
	}
	return periodic.Start(s, 500*time.Millisecond, Cfg.BS.OriginationInterval.Duration), nil
}

func (t *PeriodicTasks) startPropagator(a *net.UDPAddr) (*periodic.Runner, error) {
	topo := t.TopoProvider.Get()
	p := &beaconing.Propagator{
		Extender: t.extender("propagator", topo, maxExpTimeFactory(t.store, beacon.PropPolicy)),
		BeaconSender: &onehop.BeaconSender{
			Sender: onehop.Sender{
				Conn: t.conn,
				IA:   topo.IA(),
				MAC:  t.genMac(),
				Addr: a,
			},
			AddressRewriter:  t.addressRewriter,
			QUICBeaconSender: t.msgr,
		},
		Provider:     t.store,
		IA:           topo.IA(),
		Signer:       t.signer,
		Intfs:        t.intfs,
		AllowIsdLoop: t.allowIsdLoop,
		Core:         topo.Core(),
		Tick:         beaconing.NewTick(Cfg.BS.PropagationInterval.Duration),
	}
	return periodic.Start(p, 500*time.Millisecond, Cfg.BS.PropagationInterval.Duration), nil
}

func (t *PeriodicTasks) startSegRegRunners() (segRegRunners, error) {
	topo := t.TopoProvider.Get()
	s := segRegRunners{core: topo.Core()}
	var err error
	if s.core {
		s.coreRegistrar, err = t.startRegistrar(topo, proto.PathSegType_core, beacon.CoreRegPolicy)
		if err != nil {
			return s, common.NewBasicError("Unable to create core segment registrar", err)
		}
	} else {
		s.downRegistrar, err = t.startRegistrar(topo, proto.PathSegType_down, beacon.DownRegPolicy)
		if err != nil {
			return s, common.NewBasicError("Unable to create down segment registrar", err)
		}
		s.upRegistrar, err = t.startRegistrar(topo, proto.PathSegType_up, beacon.UpRegPolicy)
		if err != nil {
			return s, common.NewBasicError("Unable to create up segment registrar", err)
		}
	}
	return s, nil
}

func (t *PeriodicTasks) startRegistrar(topo topology.Topology, segType proto.PathSegType,
	policyType beacon.PolicyType) (*periodic.Runner, error) {

	var pather beaconing.Pather = addrutil.LegacyPather{TopoProvider: t.TopoProvider}
	if t.headerV2 {
		pather = addrutil.Pather{
			UnderlayNextHop: func(ifID uint16) (*net.UDPAddr, bool) {
				return t.TopoProvider.Get().UnderlayNextHop2(common.IFIDType(ifID))
			},
		}
	}

	r := &beaconing.Registrar{
		Extender: t.extender("registrar", topo, maxExpTimeFactory(t.store, policyType)),
		Provider: t.store,
		Store:    &seghandler.DefaultStorage{PathDB: t.pathDB},
		RPC:      beaconingcompat.RPC{Messenger: t.msgr},
		IA:       topo.IA(),
		Signer:   t.signer,
		Intfs:    t.intfs,
		Type:     segType,
		Pather:   pather,
		Tick:     beaconing.NewTick(Cfg.BS.RegistrationInterval.Duration),
	}
	return periodic.Start(r, 500*time.Millisecond, Cfg.BS.RegistrationInterval.Duration), nil
}

func (t *PeriodicTasks) extender(task string, topo topology.Topology,
	maxExp func() spath.ExpTimeType) beaconing.Extender {

	if !t.headerV2 {
		return &beaconing.LegacyExtender{
			IA:         topo.IA(),
			Signer:     t.signer,
			MAC:        t.genMac,
			Intfs:      t.intfs,
			MTU:        topo.MTU(),
			MaxExpTime: maxExp,
			StaticInfo: func() *beaconing.StaticInfoCfg { return staticInfoCfg },
			Task:       task,
		}
	}
	return &beaconing.DefaultExtender{
		IA:         topo.IA(),
		Signer:     t.signer,
		MAC:        t.genMac,
		Intfs:      t.intfs,
		MTU:        topo.MTU(),
		MaxExpTime: func() uint8 { return uint8(maxExp()) },
		StaticInfo: func() *beaconing.StaticInfoCfg { return staticInfoCfg },
		Task:       task,
	}

}

func (t *PeriodicTasks) Kill() {
	t.Mtx.Lock()
	defer t.Mtx.Unlock()
	if !t.Running {
		log.Info("Trying to stop tasks, but they are not running! Ignored.")
		return
	}
	t.registrars.Kill()
	t.revoker.Kill()
	t.Keepalive.Kill()
	t.originator.Kill()
	t.propagator.Kill()
	t.beaconCleaner.Kill()
	t.revCleaner.Kill()
	t.reissuance.Kill()
	t.corePusher.Kill()
	for i := range t.segSyncers {
		syncer := t.segSyncers[i]
		syncer.Kill()
	}
	t.pathDBCleaner.Kill()
	t.cryptosyncer.Kill()
	t.rcCleaner.Kill()
	t.nilTasks()
	t.Running = false
	log.Info("Stopped periodic tasks.")
}

func createSigner(ia addr.IA, tdb trust.DB) (cstrust.RenewingSigner, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	gen := trust.SignerGen{
		IA: itopo.Get().IA(),
		DB: cstrust.CryptoLoader{
			Dir: filepath.Join(Cfg.General.ConfigDir, "crypto/as"),
			DB:  tdb,
		},
		KeyRing: cstrust.LoadingRing{
			Dir: filepath.Join(Cfg.General.ConfigDir, "crypto/as"),
		},
	}
	cachingGen := &cstrust.CachingSignerGen{
		SignerGen: gen,
		Interval:  5 * time.Second,
	}
	_, err := cachingGen.Generate(ctx)
	if err != nil {
		return cstrust.RenewingSigner{}, err
	}
	return cstrust.RenewingSigner{
		SignerGen: cachingGen,
	}, nil
}

func macGenFactory() (func() hash.Hash, error) {
	mk, err := keyconf.LoadMaster(filepath.Join(Cfg.General.ConfigDir, "keys"))
	if err != nil {
		return nil, err
	}
	hfMacFactory, err := scrypto.HFMacFactory(mk.Key0)
	if err != nil {
		return nil, err
	}
	return hfMacFactory, nil
}

func maxExpTimeFactory(store beaconstorage.Store, p beacon.PolicyType) func() spath.ExpTimeType {
	return func() spath.ExpTimeType {
		return store.MaxExpTime(p)
	}
}

func (app *App) setup() error {
	if err := Cfg.Validate(); err != nil {
		return common.NewBasicError("Unable to validate config", err)
	}
	topo, err := topology.FromJSONFile(Cfg.General.Topology())
	if err != nil {
		return common.NewBasicError("Unable to load topology", err)
	}
	staticInfoCfg, err = beaconing.ParseStaticInfoCfg(Cfg.General.StaticInfoConfig())
	if err != nil {
		log.Info("Failed to read static info", "err", err)
	}
	// Use CS for monolith for now
	itopo.Init(
		&itopo.Config{
			ID:              Cfg.General.ID,
			Svc:             proto.ServiceType_cs,
			Callbacks:       itopo.Callbacks{OnUpdate: handleTopoUpdate},
			TopologyFactory: app.TopologyFactory,
		},
	)
	return app.runTopologyInitializer(topo)
}

func handleTopoUpdate() {
	if Intfs == nil {
		return
	}
	Intfs.Update(itopo.Get().IFInfoMap())
}

func initTopo(topo topology.Topology) error {
	if err := itopo.Update(topo); err != nil {
		return serrors.WrapStr("Unable to set initial static topology", err)
	}
	infraenv.InitInfraEnvironment(Cfg.General.Topology())
	return nil
}

func loadStore(core bool, ia addr.IA, cfg config.Config) (beaconstorage.Store, error) {
	if core {
		policies, err := LoadCorePolicies(cfg.BS.Policies)
		if err != nil {
			return nil, err
		}
		return cfg.BeaconDB.NewCoreStore(ia, policies)
	}
	policies, err := LoadPolicies(cfg.BS.Policies)
	if err != nil {
		return nil, err
	}
	return cfg.BeaconDB.NewStore(ia, policies)
}

func LoadCorePolicies(cfg config.Policies) (beacon.CorePolicies, error) {
	var err error
	var policies beacon.CorePolicies
	if policies.Prop, err = loadPolicy(cfg.Propagation, beacon.PropPolicy); err != nil {
		return policies, err
	}
	if policies.CoreReg, err = loadPolicy(cfg.CoreRegistration, beacon.CoreRegPolicy); err != nil {
		return policies, err
	}
	return policies, nil
}

func LoadPolicies(cfg config.Policies) (beacon.Policies, error) {
	var err error
	var policies beacon.Policies
	if policies.Prop, err = loadPolicy(cfg.Propagation, beacon.PropPolicy); err != nil {
		return policies, err
	}
	if policies.UpReg, err = loadPolicy(cfg.UpRegistration, beacon.UpRegPolicy); err != nil {
		return policies, err
	}
	if policies.DownReg, err = loadPolicy(cfg.DownRegistration, beacon.DownRegPolicy); err != nil {
		return policies, err
	}
	return policies, nil
}

func loadPolicy(fn string, t beacon.PolicyType) (beacon.Policy, error) {
	var policy beacon.Policy
	if fn != "" {
		p, err := beacon.LoadPolicyFromYaml(fn, t)
		if err != nil {
			return policy, common.NewBasicError("Unable to load policy", err, "fn", fn, "type", t)
		}
		policy = *p
	}
	policy.InitDefaults()
	return policy, nil
}

func CheckFlags(cfg libconfig.Sampler) (int, bool) {
	if HelpPolicy {
		var sample beacon.Policy
		sample.InitDefaults()
		raw, err := yaml.Marshal(sample)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Err: Unable to produce sample policy err=%s\n", err)
			return 1, false
		}
		os.Stdout.Write(raw)
		return 0, false
	}
	return env.CheckFlags(cfg)
}

type chainedHandler struct {
	handlers []infra.Handler
}

func (h *chainedHandler) Handle(r *infra.Request) *infra.HandlerResult {
	for _, handler := range h.handlers {
		handler.Handle(r)
	}
	// Always return success, since the metrics libraries ignore this result anyway
	return &infra.HandlerResult{
		Result: prom.Success,
		Status: prom.StatusOk,
	}
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	var buf bytes.Buffer
	toml.NewEncoder(&buf).Order(toml.OrderPreserve).Encode(Cfg)
	fmt.Fprint(w, buf.String())
}

func signerHandler(signer cstrust.RenewingSigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s, err := signer.SignerGen.Generate(r.Context())
		if err != nil {
			http.Error(w, "Unable to get signer", http.StatusInternalServerError)
			return
		}

		type Subject struct {
			IA addr.IA `json:"isd_as"`
		}
		type TRCID struct {
			ISD    addr.ISD        `json:"isd"`
			Base   scrypto.Version `json:"base_number"`
			Serial scrypto.Version `json:"serial_number"`
		}
		type Validity struct {
			NotBefore time.Time `json:"not_before"`
			NotAfter  time.Time `json:"not_after"`
		}
		rep := struct {
			Subject       Subject   `json:"subject"`
			SubjectKeyID  string    `json:"subject_key_id"`
			Expiration    time.Time `json:"expiration"`
			TRCID         TRCID     `json:"trc_id"`
			ChainValidity Validity  `json:"chain_validity"`
			InGrace       bool      `json:"in_grace_period"`
		}{
			Subject:      Subject{IA: s.IA},
			SubjectKeyID: fmt.Sprintf("% X", s.SubjectKeyID),
			Expiration:   s.Expiration,
			TRCID: TRCID{
				ISD:    s.TRCID.ISD,
				Base:   s.TRCID.Base,
				Serial: s.TRCID.Serial,
			},
			ChainValidity: Validity{
				NotBefore: s.ChainValidity.NotBefore,
				NotAfter:  s.ChainValidity.NotAfter,
			},
			InGrace: s.InGrace,
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "    ")
		if err := enc.Encode(rep); err != nil {
			http.Error(w, "Unable to marshal response", http.StatusInternalServerError)
			return
		}
	}
}
