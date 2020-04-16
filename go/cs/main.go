// Copyright 2019 Anapaya Systems
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

// The beacon server implementation.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"hash"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/cs/beacon"
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
	"github.com/scionproto/scion/go/cs/segsyncer"
	"github.com/scionproto/scion/go/cs/segutil"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/messenger/tcp"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdbmetrics"
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
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

var (
	cfg config.Config

	intfs *ifstate.Interfaces
	tasks *periodicTasks

	helpPolicy bool
)

func init() {
	flag.Usage = env.Usage
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.BoolVar(&helpPolicy, "help-policy", false, "Output sample policy file.")
	flag.Parse()
	if v, ok := checkFlags(&cfg); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped(common.CPService, cfg.General.ID)
	defer log.HandlePanic()
	if err := setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		return 1
	}
	metrics.InitBSMetrics()
	metrics.InitPSMetrics()

	pathDB, revCache, err := pathstorage.NewPathStorage(cfg.PathDB)
	if err != nil {
		log.Crit("Unable to initialize path storage", "err", err)
		return 1
	}
	defer revCache.Close()
	pathDB = pathdb.WithMetrics(string(cfg.PathDB.Backend()), pathDB)
	defer pathDB.Close()

	topo := itopo.Get()
	// Check that this process ID is present.
	if !topo.Exists(addr.SvcCS, cfg.General.ID) {
		log.Crit("Unable to find topo address for CS module")
		return 1
	}

	tracer, trCloser, err := cfg.Tracing.NewTracer(cfg.General.ID)
	if err != nil {
		log.Crit("Unable to create tracer", "err", err)
		return 1
	}
	defer trCloser.Close()
	opentracing.SetGlobalTracer(tracer)

	nc := infraenv.NetworkConfig{
		IA: topo.IA(),
		// Inherit addresses from BS; they should all match though
		// TODO(scrye): add check for addresses
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
	}
	msgr, err := nc.Messenger()
	if err != nil {
		log.Crit(infraenv.ErrAppUnableToInitMessenger.Error(), "err", err)
		return 1
	}
	defer msgr.CloseServer()

	tcpMsgr := tcp.NewServerMessenger(&net.TCPAddr{
		IP:   nc.Public.IP,
		Port: nc.Public.Port,
		Zone: nc.Public.Zone,
	})
	defer tcpMsgr.CloseServer()

	trustDB, err := cfg.TrustDB.New()
	if err != nil {
		log.Crit("Error initializing trust database", "err", err)
		return 1
	}
	trustDB = trustdbmetrics.WithMetrics(string(cfg.TrustDB.Backend()), trustDB)
	defer trustDB.Close()
	trustRouter := &segutil.Router{
		Pather: segfetcher.Pather{
			PathDB:       pathDB,
			RevCache:     revCache,
			TopoProvider: itopo.Provider(),
			// Fetcher needs to be initialized with a provider.
		},
	}
	inserter := trust.DefaultInserter{BaseInserter: trust.BaseInserter{DB: trustDB}}
	provider := trust.Provider{
		DB:       trustDB,
		Recurser: trust.ASLocalRecurser{IA: topo.IA()},
		Resolver: trust.DefaultResolver{
			DB:       trustDB,
			Inserter: inserter,
			RPC:      trust.DefaultRPC{Msgr: msgr},
			IA:       topo.IA(),
		},
		Router: trust.AuthRouter{
			ISD:    topo.IA().I,
			Router: trustRouter,
			DB:     trustDB,
		},
	}
	inspector := trust.DefaultInspector{Provider: provider}

	args := handlers.HandlerArgs{
		PathDB:          pathDB,
		RevCache:        revCache,
		ASInspector:     inspector,
		VerifierFactory: verificationFactory{Provider: provider},
		QueryInterval:   cfg.PS.QueryInterval.Duration,
		IA:              topo.IA(),
		TopoProvider:    itopo.Provider(),
		SegRequestAPI:   msgr,
	}
	trustRouter.Pather.Fetcher = segfetcher.FetcherConfig{
		QueryInterval:       cfg.PS.QueryInterval.Duration,
		LocalIA:             topo.IA(),
		VerificationFactory: verificationFactory{Provider: provider},
		PathDB:              pathDB,
		RevCache:            revCache,
		RequestAPI:          msgr,
		DstProvider:         segreq.CreateDstProvider(args, topo.Core()),
		Splitter: &segfetcher.MultiSegmentSplitter{
			Local:     topo.IA(),
			Inspector: inspector,
		},
		MetricsNamespace: metrics.PSNamespace,
		LocalInfo:        segreq.CreateLocalInfo(args, topo.Core()),
	}.New()

	trustStore := trust.Store{
		Inspector:      inspector,
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

	beaconStore, err := loadStore(topo.Core(), topo.IA(), cfg)
	if err != nil {
		log.Crit("Unable to open beacon store", "err", err)
		return 1
	}
	defer beaconStore.Close()
	intfs = ifstate.NewInterfaces(topo.IFInfoMap(), ifstate.Config{})
	prometheus.MustRegister(ifstate.NewCollector(intfs))
	chainReqHandler := trustStore.NewChainReqHandler(topo.IA())
	trcReqHandler := trustStore.NewTRCReqHandler(topo.IA())
	msgr.AddHandler(infra.ChainRequest, chainReqHandler)
	msgr.AddHandler(infra.TRCRequest, trcReqHandler)
	msgr.AddHandler(infra.Chain, trustStore.NewChainPushHandler(topo.IA()))
	msgr.AddHandler(infra.TRC, trustStore.NewTRCPushHandler(topo.IA()))
	msgr.AddHandler(infra.IfStateReq, ifstate.NewHandler(intfs))
	msgr.AddHandler(infra.Seg, beaconing.NewHandler(topo.IA(), intfs, beaconStore,
		trust.NewVerifier(trustStore)))
	msgr.AddHandler(infra.IfId, keepalive.NewHandler(topo.IA(), intfs,
		keepalive.StateChangeTasks{
			RevDropper: beaconStore,
			IfStatePusher: ifstate.PusherConf{
				Intfs:        intfs,
				Msgr:         msgr,
				TopoProvider: itopo.Provider(),
			}.New(),
		},
	))

	segReqHandler := segreq.NewHandler(args)
	msgr.AddHandler(infra.SegRequest, segReqHandler)
	msgr.AddHandler(infra.SegReg, handlers.NewSegRegHandler(args))
	if topo.Core() {
		// Old down segment sync mechanism
		msgr.AddHandler(infra.SegSync, handlers.NewSyncHandler(args))
	}
	msgr.AddHandler(infra.SignedRev, &chainedHandler{
		handlers: []infra.Handler{
			handlers.NewRevocHandler(args),
			revocation.NewHandler(beaconStore, trust.NewVerifier(trustStore), 5*time.Second),
		},
	})

	tcpMsgr.AddHandler(infra.ChainRequest, chainReqHandler)
	tcpMsgr.AddHandler(infra.TRCRequest, trcReqHandler)
	tcpMsgr.AddHandler(infra.SegRequest, segReqHandler)

	// Setup metrics and status pages
	http.HandleFunc("/config", configHandler)
	http.HandleFunc("/info", env.InfoHandler)
	http.HandleFunc("/topology", itopo.TopologyHandler)
	cfg.Metrics.StartPrometheus()
	go func() {
		defer log.HandlePanic()
		msgr.ListenAndServe()
	}()
	go func() {
		defer log.HandlePanic()
		tcpMsgr.ListenAndServe()
	}()

	dispatcherService := reliable.NewDispatcher("")
	if cfg.General.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}
	pktDisp := &snet.DefaultPacketDispatcherService{
		Dispatcher: dispatcherService,
	}
	// We do not need to drain the connection, since the src address is spoofed
	// to contain the topo address.
	ohpAddress := snet.CopyUDPAddr(topo.PublicAddress(addr.SvcBS, cfg.General.ID))
	ohpAddress.Port = 0
	conn, _, err := pktDisp.Register(context.Background(), topo.IA(), ohpAddress, addr.SvcNone)
	if err != nil {
		log.Crit("Unable to create SCION packet conn", "err", err)
		return 1
	}
	propPolicy, err := loadPolicy(cfg.BS.Policies.Propagation, beacon.PropPolicy)
	if err != nil {
		log.Crit("Unable to load propagation policy", "err", err)
		return 1
	}
	tasks = &periodicTasks{
		args:         args,
		intfs:        intfs,
		conn:         conn.(*snet.SCIONPacketConn),
		trustStore:   trustStore,
		trustDB:      trustDB,
		store:        beaconStore,
		allowIsdLoop: *propPolicy.Filter.AllowIsdLoop,
		pathDB:       pathDB,
		msgr:         msgr,
		topoProvider: itopo.Provider(),
		addressRewriter: nc.AddressRewriter(
			&onehop.OHPPacketDispatcherService{
				PacketDispatcherService: &snet.DefaultPacketDispatcherService{
					Dispatcher: reliable.NewDispatcher(""),
				},
			},
		),
	}
	msgr.UpdateSigner(signer, []infra.MessageType{infra.Seg, infra.ChainIssueRequest})
	// TODO(scrye): this breaks Interface Keepalives if it is enabled
	// msgr.UpdateVerifier(trust.NewVerifier(trustStore))

	if tasks.genMac, err = macGenFactory(); err != nil {
		log.Crit("Unable to initialize MAC generator", "err", err)
		return 1
	}

	if err := tasks.Start(); err != nil {
		log.Crit("Unable to start tasks", "err", err)
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

type periodicTasks struct {
	args            handlers.HandlerArgs
	intfs           *ifstate.Interfaces
	conn            *snet.SCIONPacketConn
	genMac          func() hash.Hash
	trustStore      trust.Store
	trustDB         trust.DB
	store           beaconstorage.Store
	pathDB          pathdb.PathDB
	msgr            infra.Messenger
	topoProvider    topology.Provider
	allowIsdLoop    bool
	addressRewriter *messenger.AddressRewriter

	keepalive  *periodic.Runner
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
	topo := t.topoProvider.Get()
	bs := topo.PublicAddress(addr.SvcBS, cfg.General.ID)
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
	if t.keepalive, err = t.startKeepaliveSender(bs); err != nil {
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

func (t *periodicTasks) startRevoker() (*periodic.Runner, error) {
	topo := t.topoProvider.Get()
	signer, err := t.createSigner(topo.IA())
	if err != nil {
		return nil, err
	}
	r := ifstate.RevokerConf{
		Intfs:        t.intfs,
		Msgr:         t.msgr,
		RevInserter:  t.store,
		Signer:       signer,
		TopoProvider: t.topoProvider,
		RevConfig: ifstate.RevConfig{
			RevTTL:     cfg.BS.RevTTL.Duration,
			RevOverlap: cfg.BS.RevOverlap.Duration,
		},
	}.New()
	return periodic.Start(r, cfg.BS.ExpiredCheckInterval.Duration,
		cfg.BS.ExpiredCheckInterval.Duration), nil
}

func (t *periodicTasks) startKeepaliveSender(a *net.UDPAddr) (*periodic.Runner, error) {
	s := &keepalive.Sender{
		Sender: &onehop.Sender{
			Conn: t.conn,
			IA:   t.topoProvider.Get().IA(),
			MAC:  t.genMac(),
			Addr: a,
		},
		Signer:       infra.NullSigner,
		TopoProvider: t.topoProvider,
	}
	return periodic.Start(s, cfg.BS.KeepaliveInterval.Duration,
		cfg.BS.KeepaliveInterval.Duration), nil
}

func (t *periodicTasks) startOriginator(a *net.UDPAddr) (*periodic.Runner, error) {
	topo := t.topoProvider.Get()
	if !topo.Core() {
		return nil, nil
	}
	signer, err := t.createSigner(topo.IA())
	if err != nil {
		return nil, err
	}
	s, err := beaconing.OriginatorConf{
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
		Config: beaconing.ExtenderConf{
			Intfs:         t.intfs,
			Mac:           t.genMac(),
			MTU:           topo.MTU(),
			Signer:        signer,
			GetMaxExpTime: maxExpTimeFactory(t.store, beacon.PropPolicy),
		},
		Period: cfg.BS.OriginationInterval.Duration,
	}.New()
	if err != nil {
		return nil, common.NewBasicError("Unable to start originator", err)
	}
	return periodic.Start(s, 500*time.Millisecond,
		cfg.BS.OriginationInterval.Duration), nil
}

func (t *periodicTasks) startPropagator(a *net.UDPAddr) (*periodic.Runner, error) {
	topo := t.topoProvider.Get()
	signer, err := t.createSigner(topo.IA())
	if err != nil {
		return nil, err
	}
	p, err := beaconing.PropagatorConf{
		BeaconProvider: t.store,
		AllowIsdLoop:   t.allowIsdLoop,
		Core:           topo.Core(),
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
		Config: beaconing.ExtenderConf{
			Intfs:         t.intfs,
			Mac:           t.genMac(),
			MTU:           topo.MTU(),
			Signer:        signer,
			GetMaxExpTime: maxExpTimeFactory(t.store, beacon.PropPolicy),
		},
		Period: cfg.BS.PropagationInterval.Duration,
	}.New()
	if err != nil {
		return nil, common.NewBasicError("Unable to start propagator", err)
	}
	return periodic.Start(p, 500*time.Millisecond,
		cfg.BS.PropagationInterval.Duration), nil
}

func (t *periodicTasks) startSegRegRunners() (segRegRunners, error) {
	topo := t.topoProvider.Get()
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

func (t *periodicTasks) startRegistrar(topo topology.Topology, segType proto.PathSegType,
	policyType beacon.PolicyType) (*periodic.Runner, error) {

	signer, err := t.createSigner(topo.IA())
	if err != nil {
		return nil, err
	}
	r, err := beaconing.RegistrarConf{
		Msgr:         t.msgr,
		SegProvider:  t.store,
		SegStore:     &seghandler.DefaultStorage{PathDB: t.pathDB},
		SegType:      segType,
		TopoProvider: t.topoProvider,
		Period:       cfg.BS.RegistrationInterval.Duration,
		Config: beaconing.ExtenderConf{
			Intfs:         t.intfs,
			Mac:           t.genMac(),
			MTU:           topo.MTU(),
			Signer:        signer,
			GetMaxExpTime: maxExpTimeFactory(t.store, policyType),
		},
	}.New()
	if err != nil {
		return nil, common.NewBasicError("unable to start registrar", err, "type", segType)
	}
	return periodic.Start(r, 500*time.Millisecond,
		cfg.BS.RegistrationInterval.Duration), nil
}

func (t *periodicTasks) createSigner(ia addr.IA) (infra.Signer, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	gen := trust.SignerGen{
		IA:       itopo.Get().IA(),
		Provider: t.trustStore,
		KeyRing: keyconf.LoadingRing{
			Dir: filepath.Join(cfg.General.ConfigDir, "keys"),
			IA:  ia,
		},
	}
	return gen.Signer(ctx)
}

func (t *periodicTasks) Kill() {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if !t.running {
		log.Warn("Trying to stop tasks, but they are not running! Ignored.")
		return
	}
	t.registrars.Kill()
	t.revoker.Kill()
	t.keepalive.Kill()
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
	t.running = false
	log.Info("Stopped periodic tasks.")
}

func macGenFactory() (func() hash.Hash, error) {
	mk, err := keyconf.LoadMaster(filepath.Join(cfg.General.ConfigDir, "keys"))
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

func setupBasic() error {
	md, err := toml.DecodeFile(env.ConfigFile(), &cfg)
	if err != nil {
		return serrors.WrapStr("Failed to load config", err, "file", env.ConfigFile())
	}
	if len(md.Undecoded()) > 0 {
		return serrors.New("Failed to load config: undecoded keys", "undecoded", md.Undecoded())
	}
	cfg.InitDefaults()
	if err := log.Setup(cfg.Logging); err != nil {
		return serrors.WrapStr("Failed to initialize logging", err)
	}
	prom.ExportElementID(cfg.General.ID)
	return env.LogAppStarted(common.CS, cfg.General.ID)
}

func setup() error {
	if err := cfg.Validate(); err != nil {
		return common.NewBasicError("Unable to validate config", err)
	}
	topo, err := topology.FromJSONFile(cfg.General.Topology())
	if err != nil {
		return common.NewBasicError("Unable to load topology", err)
	}
	// Use CS for monolith for now
	itopo.Init(
		&itopo.Config{
			ID:        cfg.General.ID,
			Svc:       proto.ServiceType_cs,
			Callbacks: itopo.Callbacks{OnUpdate: handleTopoUpdate},
		},
	)
	return initTopo(topo)
}

func handleTopoUpdate() {
	if intfs == nil {
		return
	}
	intfs.Update(itopo.Get().IFInfoMap())
}

func initTopo(topo topology.Topology) error {
	if err := itopo.Update(topo); err != nil {
		return serrors.WrapStr("Unable to set initial static topology", err)
	}
	infraenv.InitInfraEnvironment(cfg.General.Topology())
	return nil
}

func loadStore(core bool, ia addr.IA, cfg config.Config) (beaconstorage.Store, error) {
	if core {
		policies, err := loadCorePolicies(cfg.BS.Policies)
		if err != nil {
			return nil, err
		}
		return cfg.BeaconDB.NewCoreStore(ia, policies)
	}
	policies, err := loadPolicies(cfg.BS.Policies)
	if err != nil {
		return nil, err
	}
	return cfg.BeaconDB.NewStore(ia, policies)
}

func loadCorePolicies(cfg config.Policies) (beacon.CorePolicies, error) {
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

func loadPolicies(cfg config.Policies) (beacon.Policies, error) {
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

func checkFlags(cfg *config.Config) (int, bool) {
	if helpPolicy {
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

type verificationFactory struct {
	Provider trust.CryptoProvider
}

func (v verificationFactory) NewSigner(common.RawBytes, infra.SignerMeta) (infra.Signer, error) {
	return nil, serrors.New("signer generation not supported")
}

func (v verificationFactory) NewVerifier() infra.Verifier {
	return trust.NewVerifier(v.Provider)
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
	toml.NewEncoder(&buf).Encode(cfg)
	fmt.Fprint(w, buf.String())
}
