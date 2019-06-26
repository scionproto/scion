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
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/beacon_srv/internal/beaconing"
	"github.com/scionproto/scion/go/beacon_srv/internal/beaconstorage"
	"github.com/scionproto/scion/go/beacon_srv/internal/config"
	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/beacon_srv/internal/keepalive"
	"github.com/scionproto/scion/go/beacon_srv/internal/metrics"
	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/beacon_srv/internal/revocation"
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
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

var (
	cfg config.Config

	intfs *ifstate.Interfaces
	tasks *periodicTasks

	helpPoliciy bool
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
	flag.BoolVar(&helpPoliciy, "help-policy", false, "Output sample policy file.")
	flag.Parse()
	if v, ok := checkFlags(&cfg); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped(common.BS, cfg.General.ID)
	defer log.LogPanicAndExit()
	if err := setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		return 1
	}
	trustDB, err := cfg.TrustDB.New()
	if err != nil {
		log.Crit("Unable to initialize trustDB", "err", err)
		return 1
	}
	trustDB = trustdb.WithMetrics("std", trustDB)
	defer trustDB.Close()
	topo := itopo.Get()
	trustConf := &trust.Config{
		MustHaveLocalChain: true,
		ServiceType:        proto.ServiceType_bs,
	}
	trustStore := trust.NewStore(trustDB, topo.ISD_AS, trustConf, log.Root())
	err = trustStore.LoadAuthoritativeCrypto(filepath.Join(cfg.General.ConfigDir, "certs"))
	if err != nil {
		log.Crit("Unable to load local crypto", "err", err)
		return 1
	}
	topoAddress := topo.BS.GetById(cfg.General.ID)
	if topoAddress == nil {
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
	nc := infraenv.NetworkConfig{
		IA:                    topo.ISD_AS,
		Public:                env.GetPublicSnetAddress(topo.ISD_AS, topoAddress),
		Bind:                  env.GetBindSnetAddress(topo.ISD_AS, topoAddress),
		SVC:                   addr.SvcBS,
		ReconnectToDispatcher: cfg.General.ReconnectToDispatcher,
		QUIC: infraenv.QUIC{
			Address:  cfg.QUIC.Address,
			CertFile: cfg.QUIC.CertFile,
			KeyFile:  cfg.QUIC.KeyFile,
		},
		SVCResolutionFraction: cfg.QUIC.ResolutionFraction,
		TrustStore:            trustStore,
		SVCRouter:             messenger.NewSVCRouter(itopo.Provider()),
	}
	msgr, err := nc.Messenger()
	if err != nil {
		log.Crit(infraenv.ErrAppUnableToInitMessenger, "err", err)
		return 1
	}
	store, err := loadStore(topo.Core, topo.ISD_AS, cfg)
	if err != nil {
		log.Crit("Unable to open beacon store", "err", err)
		return 1
	}
	defer store.Close()
	intfs = ifstate.NewInterfaces(topo.IFInfoMap, ifstate.Config{})
	prometheus.MustRegister(ifstate.NewCollector(intfs, ""))
	msgr.AddHandler(infra.ChainRequest, trustStore.NewChainReqHandler(false))
	msgr.AddHandler(infra.TRCRequest, trustStore.NewTRCReqHandler(false))
	msgr.AddHandler(infra.IfStateReq, ifstate.NewHandler(intfs))
	msgr.AddHandler(infra.SignedRev, revocation.NewHandler(store,
		trustStore.NewVerifier(), 5*time.Second))
	msgr.AddHandler(infra.Seg, beaconing.NewHandler(topo.ISD_AS, intfs, store,
		trustStore.NewVerifier()))
	msgr.AddHandler(infra.IfId, keepalive.NewHandler(topo.ISD_AS, intfs,
		keepalive.StateChangeTasks{
			RevDropper: store,
			IfStatePusher: ifstate.PusherConf{
				Intfs:        intfs,
				Msgr:         msgr,
				TopoProvider: itopo.Provider(),
			}.New(),
		}),
	)

	cfg.Metrics.StartPrometheus()
	go func() {
		defer log.LogPanicAndExit()
		msgr.ListenAndServe()
	}()
	ovAddr := &addr.AppAddr{L3: topoAddress.PublicAddr(topoAddress.Overlay).L3}
	dispatcherService := reliable.NewDispatcherService("")
	if cfg.General.ReconnectToDispatcher {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}
	pktDisp := &snet.DefaultPacketDispatcherService{
		Dispatcher: dispatcherService,
	}
	// We do not need to drain the connection, since the src address is spoofed
	// to contain the topo address.
	conn, _, err := pktDisp.RegisterTimeout(topo.ISD_AS, ovAddr, nil, addr.SvcNone, time.Second)
	if err != nil {
		log.Crit("Unable to create SCION packet conn", "err", err)
		return 1
	}
	tasks = &periodicTasks{
		intfs:        intfs,
		conn:         conn.(*snet.SCIONPacketConn),
		trustDB:      trustDB,
		store:        store,
		msgr:         msgr,
		topoProvider: itopo.Provider(),
		addressRewriter: nc.AddressRewriter(
			&onehop.OHPPacketDispatcherService{
				PacketDispatcherService: &snet.DefaultPacketDispatcherService{
					Dispatcher: reliable.NewDispatcherService(""),
				},
			},
		),
	}
	signer, err := tasks.createSigner(topo)
	if err != nil {
		log.Crit(infraenv.ErrAppUnableToInitMessenger, "err", err)
		return 1
	}
	msgr.UpdateSigner(signer, []infra.MessageType{infra.Seg})

	if tasks.genMac, err = macGenFactory(); err != nil {
		log.Crit("Unable to initialize MAC generator", "err", err)
		return 1
	}
	discoRunners, err := idiscovery.StartRunners(cfg.Discovery, discovery.Full,
		idiscovery.TopoHandlers{}, nil)
	if err != nil {
		log.Crit("Unable to start topology fetcher", "err", err)
		return 1
	}
	defer discoRunners.Kill()
	if err := tasks.Start(); err != nil {
		log.Crit("Unable to start leader tasks", "err", err)
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
	if s.core {
		s.coreRegistrar.Kill()
		return
	}
	s.upRegistrar.Kill()
	s.downRegistrar.Kill()
}

type periodicTasks struct {
	intfs           *ifstate.Interfaces
	conn            *snet.SCIONPacketConn
	genMac          func() hash.Hash
	trustDB         trustdb.TrustDB
	store           beaconstorage.Store
	msgr            infra.Messenger
	topoProvider    topology.Provider
	allowIsdLoop    bool
	addressRewriter *messenger.AddressRewriter

	keepalive  *periodic.Runner
	originator *periodic.Runner
	propagator *periodic.Runner
	revoker    *periodic.Runner
	registrars segRegRunners

	beaconCleaner *periodic.Runner
	revCleaner    *periodic.Runner

	mtx     sync.Mutex
	running bool
}

func (t *periodicTasks) Start() error {
	fatal.Check()
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if t.running {
		log.Warn("Trying to start task, but they are running! Ignored.")
		return nil
	}
	topo := t.topoProvider.Get()
	topoAddress := topo.BS.GetById(cfg.General.ID)
	if topoAddress == nil {
		return common.NewBasicError("Unable to find topo address", nil)
	}
	var err error
	if t.registrars, err = t.startSegRegRunners(); err != nil {
		return err
	}
	if t.revoker, err = t.startRevoker(); err != nil {
		return err
	}
	if t.keepalive, err = t.startKeepaliveSender(topoAddress); err != nil {
		return err
	}
	if t.originator, err = t.startOriginator(topoAddress); err != nil {
		return err
	}
	if t.propagator, err = t.startPropagator(topoAddress); err != nil {
		return err
	}
	t.beaconCleaner = periodic.StartPeriodicTask(
		beaconstorage.NewBeaconCleaner(t.store),
		periodic.NewTicker(30*time.Second), 30*time.Second,
	)
	t.revCleaner = periodic.StartPeriodicTask(
		beaconstorage.NewRevocationCleaner(t.store),
		periodic.NewTicker(5*time.Second), 5*time.Second,
	)
	t.running = true
	return nil
}

func (t *periodicTasks) startRevoker() (*periodic.Runner, error) {
	topo := t.topoProvider.Get()
	signer, err := t.createSigner(topo)
	if err != nil {
		return nil, err
	}
	r := ifstate.RevokerConf{
		Intfs:        t.intfs,
		Msgr:         t.msgr,
		RevInserter:  t.store,
		Signer:       signer,
		TopoProvider: t.topoProvider,
		// TODO(roosd): Make RevConfig configurable
	}.New()
	return periodic.StartPeriodicTask(r, periodic.NewTicker(cfg.BS.ExpiredCheckInterval.Duration),
		cfg.BS.ExpiredCheckInterval.Duration), nil
}

func (t *periodicTasks) startKeepaliveSender(a *topology.TopoAddr) (*periodic.Runner, error) {
	s := &keepalive.Sender{
		Sender: &onehop.Sender{
			Conn: t.conn,
			IA:   t.topoProvider.Get().ISD_AS,
			MAC:  t.genMac(),
			Addr: a.PublicAddr(a.Overlay),
		},
		Signer:       infra.NullSigner,
		TopoProvider: t.topoProvider,
	}
	return periodic.StartPeriodicTask(s, periodic.NewTicker(cfg.BS.KeepaliveInterval.Duration),
		cfg.BS.KeepaliveInterval.Duration), nil
}

func (t *periodicTasks) startOriginator(a *topology.TopoAddr) (*periodic.Runner, error) {
	topo := t.topoProvider.Get()
	if !topo.Core {
		return nil, nil
	}
	signer, err := t.createSigner(topo)
	if err != nil {
		return nil, err
	}
	s, err := beaconing.OriginatorConf{
		EnableMetrics: true,
		BeaconSender: &onehop.BeaconSender{
			Sender: onehop.Sender{
				Conn: t.conn,
				IA:   topo.ISD_AS,
				MAC:  t.genMac(),
				Addr: a.PublicAddr(a.Overlay),
			},
			AddressRewriter:  t.addressRewriter,
			QUICBeaconSender: t.msgr,
		},
		Config: beaconing.ExtenderConf{
			Intfs:  t.intfs,
			Mac:    t.genMac(),
			MTU:    uint16(topo.MTU),
			Signer: signer,
		},
		Period: cfg.BS.OriginationInterval.Duration,
	}.New()
	if err != nil {
		return nil, common.NewBasicError("Unable to start originator", err)
	}
	return periodic.StartPeriodicTask(s, periodic.NewTicker(500*time.Millisecond),
		cfg.BS.OriginationInterval.Duration), nil
}

func (t *periodicTasks) startPropagator(a *topology.TopoAddr) (*periodic.Runner, error) {
	topo := t.topoProvider.Get()
	signer, err := t.createSigner(topo)
	if err != nil {
		return nil, err
	}
	p, err := beaconing.PropagatorConf{
		BeaconProvider: t.store,
		AllowIsdLoop:   t.allowIsdLoop,
		Core:           topo.Core,
		EnableMetrics:  true,
		BeaconSender: &onehop.BeaconSender{
			Sender: onehop.Sender{
				Conn: t.conn,
				IA:   topo.ISD_AS,
				MAC:  t.genMac(),
				Addr: a.PublicAddr(a.Overlay),
			},
			AddressRewriter:  t.addressRewriter,
			QUICBeaconSender: t.msgr,
		},
		Config: beaconing.ExtenderConf{
			Intfs:  t.intfs,
			Mac:    t.genMac(),
			MTU:    uint16(topo.MTU),
			Signer: signer,
		},
		Period: cfg.BS.PropagationInterval.Duration,
	}.New()
	if err != nil {
		return nil, common.NewBasicError("Unable to start propagator", err)
	}
	return periodic.StartPeriodicTask(p, periodic.NewTicker(500*time.Millisecond),
		cfg.BS.PropagationInterval.Duration), nil
}

func (t *periodicTasks) startSegRegRunners() (segRegRunners, error) {
	topo := t.topoProvider.Get()
	s := segRegRunners{core: topo.Core}
	var err error
	if s.core {
		if s.coreRegistrar, err = t.startRegistrar(topo, proto.PathSegType_core); err != nil {
			return s, common.NewBasicError("Unable to create core segment registrar", err)
		}
	} else {
		if s.downRegistrar, err = t.startRegistrar(topo, proto.PathSegType_down); err != nil {
			return s, common.NewBasicError("Unable to create down segment registrar", err)
		}
		if s.upRegistrar, err = t.startRegistrar(topo, proto.PathSegType_up); err != nil {
			return s, common.NewBasicError("Unable to create up segment registrar", err)
		}
	}
	return s, nil
}

func (t *periodicTasks) startRegistrar(topo *topology.Topo,
	segType proto.PathSegType) (*periodic.Runner, error) {

	signer, err := t.createSigner(topo)
	if err != nil {
		return nil, err
	}
	r, err := beaconing.RegistrarConf{
		Msgr:          t.msgr,
		SegProvider:   t.store,
		SegType:       segType,
		TopoProvider:  t.topoProvider,
		Period:        cfg.BS.RegistrationInterval.Duration,
		EnableMetrics: true,
		Config: beaconing.ExtenderConf{
			Intfs:  t.intfs,
			Mac:    t.genMac(),
			MTU:    uint16(topo.MTU),
			Signer: signer,
		},
	}.New()
	if err != nil {
		return nil, common.NewBasicError("Unable to start registrar", err, "type", segType)
	}
	return periodic.StartPeriodicTask(r, periodic.NewTicker(500*time.Millisecond),
		cfg.BS.RegistrationInterval.Duration), nil
}

func (t *periodicTasks) createSigner(topo *topology.Topo) (infra.Signer, error) {
	dir := filepath.Join(cfg.General.ConfigDir, "keys")
	cfg, err := keyconf.Load(dir, false, false, false, false)
	if err != nil {
		return nil, common.NewBasicError("Unable to load key config", err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	meta, err := trust.CreateSignMeta(ctx, topo.ISD_AS, t.trustDB)
	if err != nil {
		return nil, common.NewBasicError("Unable to create sign meta", err)
	}
	signer, err := trust.NewBasicSigner(cfg.SignKey, meta)
	if err != nil {
		return nil, common.NewBasicError("Unable to create signer", err)
	}
	return signer, nil
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
	if t.originator != nil {
		t.originator.Kill()
	}
	t.propagator.Kill()
	t.beaconCleaner.Kill()
	t.revCleaner.Kill()
	t.running = false
}

func macGenFactory() (func() hash.Hash, error) {
	mk, err := keyconf.LoadMaster(filepath.Join(cfg.General.ConfigDir, "keys"))
	if err != nil {
		return nil, err
	}
	hfGenKey := pbkdf2.Key(mk.Key0, []byte("Derive OF Key"), 1000, 16, sha256.New)
	// check that mac initialization works.
	if _, err := scrypto.InitMac(hfGenKey); err != nil {
		return nil, err
	}
	gen := func() hash.Hash {
		mac, _ := scrypto.InitMac(hfGenKey)
		return mac
	}
	return gen, nil
}

func setupBasic() error {
	if _, err := toml.DecodeFile(env.ConfigFile(), &cfg); err != nil {
		return err
	}
	cfg.InitDefaults()
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return err
	}
	metrics.Init(cfg.General.ID)
	return env.LogAppStarted(common.BS, cfg.General.ID)
}

func setup() error {
	if err := cfg.Validate(); err != nil {
		return common.NewBasicError("Unable to validate config", err)
	}
	clbks := itopo.Callbacks{UpdateStatic: handleTopoUpdate}
	itopo.Init(cfg.General.ID, proto.ServiceType_bs, clbks)
	topo, err := topology.LoadFromFile(cfg.General.Topology)
	if err != nil {
		return common.NewBasicError("Unable to load topology", err)
	}
	if _, _, err := itopo.SetStatic(topo, false); err != nil {
		return common.NewBasicError("Unable to set initial static topology", err)
	}
	infraenv.InitInfraEnvironment(cfg.General.Topology)
	return nil
}

func handleTopoUpdate() {
	if intfs == nil {
		return
	}
	intfs.Update(itopo.Get().IFInfoMap)
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
		p, err := beacon.LoadFromYaml(fn, t)
		if err != nil {
			return policy, common.NewBasicError("Unable to load policy", err, "fn", fn, "type", t)
		}
		policy = *p
	}
	policy.InitDefaults()
	return policy, nil
}

func checkFlags(cfg *config.Config) (int, bool) {
	if helpPoliciy {
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
