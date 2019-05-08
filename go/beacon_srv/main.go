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
	"golang.org/x/crypto/pbkdf2"

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
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

var (
	cfg         config.Config
	environment *env.Env

	intfs *ifstate.Interfaces
	tasks *periodicTasks
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
	flag.Parse()
	if v, ok := env.CheckFlags(&cfg); !ok {
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
	trustStore, err := trust.NewStore(trustDB, topo.ISD_AS, trustConf, log.Root())
	if err != nil {
		log.Crit("Unable to initialize trust store", "err", err)
		return 1
	}
	err = trustStore.LoadAuthoritativeTRC(filepath.Join(cfg.General.ConfigDir, "certs"))
	if err != nil {
		log.Crit("TRC error", "err", err)
		return 1
	}
	err = trustStore.LoadAuthoritativeChain(filepath.Join(cfg.General.ConfigDir, "certs"))
	if err != nil {
		log.Crit("Chain error", "err", err)
		return 1
	}
	topoAddress := topo.BS.GetById(cfg.General.ID)
	if topoAddress == nil {
		log.Crit("Unable to find topo address")
		return 1
	}
	nc := infraenv.NetworkConfig{
		IA:                    topo.ISD_AS,
		Public:                env.GetPublicSnetAddress(topo.ISD_AS, topoAddress),
		Bind:                  env.GetBindSnetAddress(topo.ISD_AS, topoAddress),
		SVC:                   addr.SvcBS,
		ReconnectToDispatcher: cfg.General.ReconnectToDispatcher,
		EnableQUICTest:        cfg.EnableQUICTest,
		TrustStore:            trustStore,
	}
	msgr, err := nc.Messenger()
	if err != nil {
		log.Crit(infraenv.ErrAppUnableToInitMessenger, "err", err)
		return 1
	}
	var store beaconstorage.Store
	if topo.Core {
		store, err = cfg.BeaconDB.NewCoreStore(topo.ISD_AS, beacon.CorePolicies{})
	} else {
		store, err = cfg.BeaconDB.NewStore(topo.ISD_AS, beacon.Policies{})
	}
	if err != nil {
		log.Crit("Unable to open beacon store", "err", err)
		return 1
	}
	intfs = ifstate.NewInterfaces(topo.IFInfoMap, ifstate.Config{})
	msgr.AddHandler(infra.ChainRequest, trustStore.NewChainReqHandler(false))
	msgr.AddHandler(infra.TRCRequest, trustStore.NewTRCReqHandler(false))
	msgr.AddHandler(infra.IfStateReq, ifstate.NewHandler(intfs))
	msgr.AddHandler(infra.IfId, keepalive.NewHandler(topo.ISD_AS, intfs, keepaliveTasks()))
	msgr.AddHandler(infra.SignedRev, revocation.NewHandler(store,
		trustStore.NewVerifier(), 5*time.Second))
	msgr.AddHandler(infra.Seg, beaconing.NewHandler(topo.ISD_AS, intfs, store,
		trustStore.NewVerifier()))
	cfg.Metrics.StartPrometheus()
	go func() {
		defer log.LogPanicAndExit()
		msgr.ListenAndServe()
	}()
	ovAddr := &addr.AppAddr{L3: topoAddress.PublicAddr(topoAddress.Overlay).L3}
	pktDisp := snet.NewDefaultPacketDispatcherService(reliable.NewDispatcherService(""))
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
	}
	if tasks.genMac, err = macGenFactory(); err != nil {
		log.Crit("Unable to initialize MAC generator", "err", err)
		return 1
	}
	if err := tasks.Start(); err != nil {
		log.Crit("Unable to start leader tasks", "err", err)
		return 1
	}
	defer tasks.Kill()
	select {
	case <-environment.AppShutdownSignal:
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		return 0
	case <-fatal.Chan():
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
	intfs        *ifstate.Interfaces
	conn         *snet.SCIONPacketConn
	genMac       func() hash.Hash
	trustDB      trustdb.TrustDB
	store        beaconstorage.Store
	msgr         infra.Messenger
	topoProvider topology.Provider

	keepalive  *periodic.Runner
	originator *periodic.Runner
	propagator *periodic.Runner
	revoker    *periodic.Runner
	registrars segRegRunners
	discovery  idiscovery.Runners

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
	if t.discovery, err = t.startDiscovery(); err != nil {
		return err
	}
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

func (t *periodicTasks) startDiscovery() (idiscovery.Runners, error) {
	d, err := idiscovery.StartRunners(cfg.Discovery, discovery.Full, idiscovery.TopoHandlers{}, nil)
	if err != nil {
		return idiscovery.Runners{}, common.NewBasicError("Unable to start topology fetcher", err)
	}
	return d, nil
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
		Sender: &onehop.Sender{
			Conn: t.conn,
			IA:   topo.ISD_AS,
			MAC:  t.genMac(),
			Addr: a.PublicAddr(a.Overlay),
		},
		Config: beaconing.ExtenderConf{
			Intfs:  t.intfs,
			Mac:    t.genMac(),
			MTU:    uint16(topo.MTU),
			Signer: signer,
		},
	}.New()
	if err != nil {
		return nil, common.NewBasicError("Unable to start originator", err)
	}
	return periodic.StartPeriodicTask(s, periodic.NewTicker(cfg.BS.OriginationInterval.Duration),
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
		Core:           topo.Core,
		Sender: &onehop.Sender{
			Conn: t.conn,
			IA:   topo.ISD_AS,
			MAC:  t.genMac(),
			Addr: a.PublicAddr(a.Overlay),
		},
		Config: beaconing.ExtenderConf{
			Intfs:  t.intfs,
			Mac:    t.genMac(),
			MTU:    uint16(topo.MTU),
			Signer: signer,
		},
	}.New()
	if err != nil {
		return nil, common.NewBasicError("Unable to start propagator", err)
	}
	return periodic.StartPeriodicTask(p, periodic.NewTicker(cfg.BS.PropagationInterval.Duration),
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
		Msgr:         t.msgr,
		SegProvider:  t.store,
		SegType:      segType,
		TopoProvider: t.topoProvider,
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
	return periodic.StartPeriodicTask(r, periodic.NewTicker(cfg.BS.RegistrationInterval.Duration),
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
	t.discovery.Kill()
	t.keepalive.Kill()
	if t.originator != nil {
		t.originator.Kill()
	}
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
	return env.LogAppStarted(common.CS, cfg.General.ID)
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
	environment = infraenv.InitInfraEnvironment(cfg.General.Topology)
	return nil
}

func handleTopoUpdate() {
	if intfs == nil {
		log.Warn("intfs not set, ignoring static update")
		return
	}
	intfs.Update(itopo.Get().IFInfoMap)
}

func keepaliveTasks() keepalive.StateChangeTasks {
	return keepalive.StateChangeTasks{
		Beaconer:      keepaliveMocker{},
		IfStatePusher: keepaliveMocker{},
		RevDropper:    keepaliveMocker{},
	}
}

// FIXME(roosd): Implement appropriate callbacks.
type keepaliveMocker struct{}

func (keepaliveMocker) Push(_ context.Context) {}

func (keepaliveMocker) Beacon(_ context.Context, _ common.IFIDType) {}

func (keepaliveMocker) DeleteRevocation(_ context.Context, _ addr.IA,
	_ common.IFIDType) (int, error) {

	return 0, nil
}
