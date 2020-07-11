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

package cs

import (
	"context"
	"hash"
	"net"
	"time"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing"
	beaconingcompat "github.com/scionproto/scion/go/cs/beaconing/compat"
	"github.com/scionproto/scion/go/cs/beaconstorage"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/keepalive"
	"github.com/scionproto/scion/go/cs/onehop"
	"github.com/scionproto/scion/go/cs/segsyncer"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

// TasksConfig holds the necessary configuration to start the periodic tasks a
// CS is expected to run.
type TasksConfig struct {
	Public          *net.UDPAddr
	Intfs           *ifstate.Interfaces
	OneHopConn      snet.PacketConn
	TrustDB         trust.DB
	PathDB          pathdb.PathDB
	RevCache        revcache.RevCache
	BeaconStore     beaconstorage.Store
	Signer          ctrl.Signer
	Msgr            infra.Messenger
	AddressRewriter *messenger.AddressRewriter
	Inspector       trust.Inspector

	MACGen       func() hash.Hash
	TopoProvider topology.Provider
	StaticInfo   func() *beaconing.StaticInfoCfg

	OriginationInterval  time.Duration
	PropagationInterval  time.Duration
	RegistrationInterval time.Duration

	AllowIsdLoop bool
	HeaderV2     bool
}

// SegSyncers creates a segment syncer tasks for every other core AS in the
// local ISD if the local AS is a core AS.
func (t *TasksConfig) SegSyncers() ([]*periodic.Runner, error) {
	if !itopo.Get().Core() {
		return nil, nil
	}
	return segsyncer.StartAll(segsyncer.Config{
		IA:        itopo.Get().IA(),
		Inspector: t.Inspector,
		PathDB:    t.PathDB,
		RevCache:  t.RevCache,
		Msgr:      t.Msgr,
		Pather:    NewPather(t.TopoProvider, t.HeaderV2),
	})
}

// Originator starts a periodic beacon origination task. For non-core ASes, no
// periodic runner is started.
func (t *TasksConfig) Originator() *periodic.Runner {
	topo := t.TopoProvider.Get()
	if !topo.Core() {
		return nil
	}
	s := &beaconing.Originator{
		Extender: t.extender("originator", topo.IA(), topo.MTU(), func() spath.ExpTimeType {
			return t.BeaconStore.MaxExpTime(beacon.PropPolicy)
		}),
		BeaconSender: &onehop.BeaconSender{
			Sender: onehop.Sender{
				Conn:     t.OneHopConn,
				IA:       topo.IA(),
				MAC:      t.MACGen(),
				Addr:     t.Public,
				HeaderV2: t.HeaderV2,
			},
			AddressRewriter:  t.AddressRewriter,
			QUICBeaconSender: t.Msgr,
		},
		IA:     topo.IA(),
		Intfs:  t.Intfs,
		Signer: t.Signer,
		Tick:   beaconing.NewTick(t.OriginationInterval),
	}
	return periodic.Start(s, 500*time.Millisecond, t.OriginationInterval)
}

// Propagator starts a periodic beacon propagation task.
func (t *TasksConfig) Propagator() *periodic.Runner {
	topo := t.TopoProvider.Get()
	p := &beaconing.Propagator{
		Extender: t.extender("propagator", topo.IA(), topo.MTU(), func() spath.ExpTimeType {
			return t.BeaconStore.MaxExpTime(beacon.PropPolicy)
		}),
		BeaconSender: &onehop.BeaconSender{
			Sender: onehop.Sender{
				Conn:     t.OneHopConn,
				IA:       topo.IA(),
				MAC:      t.MACGen(),
				Addr:     t.Public,
				HeaderV2: t.HeaderV2,
			},
			AddressRewriter:  t.AddressRewriter,
			QUICBeaconSender: t.Msgr,
		},
		Provider:     t.BeaconStore,
		IA:           topo.IA(),
		Signer:       t.Signer,
		Intfs:        t.Intfs,
		AllowIsdLoop: t.AllowIsdLoop,
		Core:         topo.Core(),
		Tick:         beaconing.NewTick(t.PropagationInterval),
	}
	return periodic.Start(p, 500*time.Millisecond, t.PropagationInterval)
}

// Registrars starts periodic segment registration tasks.
func (t *TasksConfig) Registrars() []*periodic.Runner {
	topo := t.TopoProvider.Get()
	if topo.Core() {
		return []*periodic.Runner{t.registrar(topo, proto.PathSegType_core, beacon.CoreRegPolicy)}
	}
	return []*periodic.Runner{
		t.registrar(topo, proto.PathSegType_down, beacon.DownRegPolicy),
		t.registrar(topo, proto.PathSegType_up, beacon.UpRegPolicy),
	}
}

func (t *TasksConfig) registrar(topo topology.Topology, segType proto.PathSegType,
	policyType beacon.PolicyType) *periodic.Runner {

	pather := NewPather(t.TopoProvider, t.HeaderV2)
	r := &beaconing.Registrar{
		Extender: t.extender("registrar", topo.IA(), topo.MTU(), func() spath.ExpTimeType {
			return t.BeaconStore.MaxExpTime(policyType)
		}),
		Provider: t.BeaconStore,
		Store:    &seghandler.DefaultStorage{PathDB: t.PathDB},
		RPC:      beaconingcompat.RPC{Messenger: t.Msgr},
		IA:       topo.IA(),
		Signer:   t.Signer,
		Intfs:    t.Intfs,
		Type:     segType,
		Pather:   pather,
		Tick:     beaconing.NewTick(t.RegistrationInterval),
	}
	return periodic.Start(r, 500*time.Millisecond, t.RegistrationInterval)
}

func (t *TasksConfig) extender(task string, ia addr.IA, mtu uint16,
	maxExp func() spath.ExpTimeType) beaconing.Extender {

	if !t.HeaderV2 {
		return &beaconing.LegacyExtender{
			IA:         ia,
			Signer:     t.Signer,
			MAC:        t.MACGen,
			Intfs:      t.Intfs,
			MTU:        mtu,
			MaxExpTime: maxExp,
			StaticInfo: t.StaticInfo,
			Task:       task,
		}
	}
	return &beaconing.DefaultExtender{
		IA:         ia,
		Signer:     t.Signer,
		MAC:        t.MACGen,
		Intfs:      t.Intfs,
		MTU:        mtu,
		MaxExpTime: func() uint8 { return uint8(maxExp()) },
		StaticInfo: t.StaticInfo,
		Task:       task,
	}
}

// Tasks keeps track of the running tasks.
type Tasks struct {
	Originator *periodic.Runner
	Propagator *periodic.Runner
	Registrars []*periodic.Runner

	SegSyncers []*periodic.Runner

	BeaconCleaner *periodic.Runner
	PathCleaner   *periodic.Runner
}

func StartTasks(cfg TasksConfig) (*Tasks, error) {
	segSyncers, err := cfg.SegSyncers()
	if err != nil {
		return nil, serrors.WrapStr("starting segment syncers", err)
	}

	beaconCleaner := beaconstorage.NewBeaconCleaner(cfg.BeaconStore)
	revCleaner := beaconstorage.NewRevocationCleaner(cfg.BeaconStore)

	segCleaner := pathdb.NewCleaner(cfg.PathDB, "ps_segments")
	segRevCleaner := revcache.NewCleaner(cfg.RevCache, "ps_revocation")
	return &Tasks{
		SegSyncers: segSyncers,
		Originator: cfg.Originator(),
		Propagator: cfg.Propagator(),
		Registrars: cfg.Registrars(),
		BeaconCleaner: periodic.Start(
			periodic.Func{
				Task: func(ctx context.Context) {
					beaconCleaner.Run(ctx)
					revCleaner.Run(ctx)
				},
				TaskName: "beaconstorage_cleaner",
			},
			30*time.Second,
			30*time.Second,
		),
		PathCleaner: periodic.Start(
			periodic.Func{
				Task: func(ctx context.Context) {
					segCleaner.Run(ctx)
					segRevCleaner.Run(ctx)
				},
			},
			10*time.Second,
			10*time.Second,
		),
	}, nil

}

// Kill stops all running tasks immediately.
func (t *Tasks) Kill() {
	if t == nil {
		return
	}
	killRunners([]*periodic.Runner{
		t.Originator,
		t.Propagator,
		t.BeaconCleaner,
		t.PathCleaner,
	})
	killRunners(t.SegSyncers)
	killRunners(t.Registrars)
	t.Originator = nil
	t.Propagator = nil
	t.BeaconCleaner = nil
	t.PathCleaner = nil
	t.SegSyncers = nil
	t.Registrars = nil
}

// LegacyTasks keeps track of tasks running in legacy behavior.
type LegacyTasks struct {
	Keepalive *periodic.Runner
	Revoker   *periodic.Runner
}

func StartLegacyTasks(cfg LegacyTasksConfig) *LegacyTasks {
	return &LegacyTasks{
		Keepalive: cfg.Keepalive(),
		Revoker:   cfg.Revoker(),
	}
}

func (t *LegacyTasks) Kill() {
	if t == nil {
		return
	}
	killRunners([]*periodic.Runner{
		t.Keepalive,
		t.Revoker,
	})
	t.Keepalive = nil
	t.Revoker = nil
}

// LegacyTasksConfig holds the necessary configuration to start the periodic
// tasks a CS is expected to run when running in header v1 mode. The tasks take
// care of the keepalive and revocation mechanism. It will be replaced
// by BR to BR health checking and be obsolete when switching to header v2.
type LegacyTasksConfig struct {
	Public      *net.UDPAddr
	Intfs       *ifstate.Interfaces
	OneHopConn  *snet.SCIONPacketConn
	BeaconStore beaconstorage.Store
	Signer      ctrl.Signer
	Msgr        infra.Messenger

	MACGen       func() hash.Hash
	TopoProvider topology.Provider

	KeepaliveInterval    time.Duration
	ExpiredCheckInterval time.Duration
	RevTTL               time.Duration
	RevOverlap           time.Duration

	HeaderV2 bool
}

// Keepalive starts a keepalive sender.
func (t LegacyTasksConfig) Keepalive() *periodic.Runner {
	r := periodic.Start(
		&keepalive.Sender{
			Sender: &onehop.Sender{
				Conn:     t.OneHopConn,
				IA:       t.TopoProvider.Get().IA(),
				MAC:      t.MACGen(),
				Addr:     t.Public,
				HeaderV2: t.HeaderV2,
			},
			Signer:       infra.NullSigner,
			TopoProvider: t.TopoProvider,
		},
		t.KeepaliveInterval,
		t.KeepaliveInterval,
	)
	r.TriggerRun()
	return r
}

// Revoker starts a periodic tasks that checks if interfaces need to be revoked.
func (t LegacyTasksConfig) Revoker() *periodic.Runner {
	return periodic.Start(
		ifstate.RevokerConf{
			Intfs:        t.Intfs,
			Msgr:         t.Msgr,
			RevInserter:  t.BeaconStore,
			Signer:       t.Signer,
			TopoProvider: t.TopoProvider,
			RevConfig: ifstate.RevConfig{
				RevTTL:     t.RevTTL,
				RevOverlap: t.RevOverlap,
			},
		}.New(),
		t.ExpiredCheckInterval,
		t.ExpiredCheckInterval,
	)
}

func killRunners(runners []*periodic.Runner) {
	for _, r := range runners {
		r.Kill()
	}
}
