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

package control

import (
	"context"
	"hash"
	"net"
	"time"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/drkey"
	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/trust"
)

// TasksConfig holds the necessary configuration to start the periodic tasks a
// CS is expected to run.
type TasksConfig struct {
	Core       bool
	IA         addr.IA
	MTU        uint16
	NextHopper interface {
		UnderlayNextHop(uint16) *net.UDPAddr
	}
	Public                *net.UDPAddr
	AllInterfaces         *ifstate.Interfaces
	PropagationInterfaces func() []*ifstate.Interface
	OriginationInterfaces func() []*ifstate.Interface
	TrustDB               trust.DB
	PathDB                pathdb.DB
	RevCache              revcache.RevCache
	BeaconSenderFactory   beaconing.SenderFactory
	SegmentRegister       beaconing.RPC
	BeaconStore           Store
	SignerGen             beaconing.SignerGen
	Inspector             trust.Inspector
	Metrics               *Metrics
	DRKeyEngine           *drkey.ServiceEngine

	MACGen     func() hash.Hash
	StaticInfo func() *beaconing.StaticInfoCfg

	OriginationInterval  time.Duration
	PropagationInterval  time.Duration
	RegistrationInterval time.Duration
	DRKeyEpochInterval   time.Duration
	// HiddenPathRegistrationCfg contains the required options to configure
	// hidden paths down segment registration. If it is nil, normal path
	// registration is used instead.
	HiddenPathRegistrationCfg *HiddenPathRegistrationCfg

	AllowIsdLoop bool

	EPIC bool

	registrars SegmentRegistrars
}

// InitPlugins initializes the segment registration plugins based on the provided
// registration policies. This must be called before starting the tasks.
func (t *TasksConfig) InitPlugins(ctx context.Context, policies []beacon.Policy) error {
	if t.registrars != nil {
		return nil
	}
	// Initialize the segment registrars.
	segmentRegistrars := make(SegmentRegistrars)
	for _, policy := range policies {
		for _, regPolicy := range policy.RegistrationPolicies {
			plugin, ok := GetPlugin(regPolicy.Plugin)
			if !ok {
				return serrors.New("unknown segment registration plugin",
					"plugin", regPolicy.Plugin)
			}
			segType, ok := SegmentTypeFromPolicyType(policy.Type)
			if !ok {
				return serrors.New("unsupported policy type for segment registration plugin",
					"policy_type", policy.Type)
			}
			registrar, err := plugin.New(ctx, t, segType, policy.Type, regPolicy.PluginConfig)
			if err != nil {
				return serrors.Wrap("creating segment registrar", err)
			}
			if err := segmentRegistrars.Register(
				policy.Type, regPolicy.Name, registrar,
			); err != nil {
				return serrors.Wrap("registering segment registrar", err,
					"policy_type", policy.Type, "registration_policy", regPolicy.Name)
			}
		}
	}
	// For the policy types that do not have any plugins registered, we construct a registrar from
	// the default plugin.
	// This is done for the sake of backward compatibility.
	defaultPlugin := DefaultSegmentRegistrationPlugin{}
	for _, policyType := range []beacon.PolicyType{
		beacon.UpRegPolicy,
		beacon.DownRegPolicy,
		beacon.CoreRegPolicy,
	} {
		if _, ok := segmentRegistrars[policyType]; !ok {
			segType, _ := SegmentTypeFromPolicyType(policyType)
			defaultRegistrar, err := defaultPlugin.New(
				ctx, t, segType, policyType, nil,
			)
			if err != nil {
				return serrors.Wrap("creating default segment registrar", err,
					"policy_type", policyType)
			}
			if err := segmentRegistrars.RegisterDefault(
				policyType, defaultRegistrar,
			); err != nil {
				return serrors.Wrap("registering default segment registrar", err,
					"policy_type", policyType)
			}
		}
	}
	t.registrars = segmentRegistrars
	return nil
}

// Originator starts a periodic beacon origination task. For non-core ASes, no
// periodic runner is started.
func (t *TasksConfig) Originator() *periodic.Runner {
	if !t.Core {
		return nil
	}
	s := &beaconing.Originator{
		Extender: t.extender("originator", t.IA, t.MTU, func() uint8 {
			return t.BeaconStore.MaxExpTime(beacon.PropPolicy)
		}),
		SenderFactory:         t.BeaconSenderFactory,
		IA:                    t.IA,
		AllInterfaces:         t.AllInterfaces,
		OriginationInterfaces: t.OriginationInterfaces,
		Tick:                  beaconing.NewTick(t.OriginationInterval),
	}
	if t.Metrics != nil {
		s.Originated = metrics.NewPromCounter(t.Metrics.BeaconingOriginatedTotal)
	}
	//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
	return periodic.Start(s, 500*time.Millisecond, t.OriginationInterval)
}

// Propagator starts a periodic beacon propagation task.
func (t *TasksConfig) Propagator() *periodic.Runner {
	p := &beaconing.Propagator{
		Extender: t.extender("propagator", t.IA, t.MTU, func() uint8 {
			return t.BeaconStore.MaxExpTime(beacon.PropPolicy)
		}),
		SenderFactory:         t.BeaconSenderFactory,
		Provider:              t.BeaconStore,
		IA:                    t.IA,
		AllInterfaces:         t.AllInterfaces,
		PropagationInterfaces: t.PropagationInterfaces,
		AllowIsdLoop:          t.AllowIsdLoop,
		Tick:                  beaconing.NewTick(t.PropagationInterval),
	}
	if t.Metrics != nil {
		p.Propagated = metrics.NewPromCounter(t.Metrics.BeaconingPropagatedTotal)
		p.InternalErrors = metrics.NewPromCounter(t.Metrics.BeaconingPropagatorInternalErrorsTotal)
	}
	//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
	return periodic.Start(p, 500*time.Millisecond, t.PropagationInterval)
}

// SegmentWriters starts periodic segment registration tasks.
func (t *TasksConfig) SegmentWriters() []*periodic.Runner {
	if t.Core {
		return []*periodic.Runner{t.segmentWriter(beacon.CoreRegPolicy)}
	}
	return []*periodic.Runner{
		t.segmentWriter(beacon.DownRegPolicy),
		t.segmentWriter(beacon.UpRegPolicy),
	}
}

// RegistrarWriter is a beaconing.Writer that invokes the correct segment registrar
// from the Plugins depending on PolicyType.
type RegistrarWriter struct {
	PolicyType beacon.PolicyType
	Plugins    SegmentRegistrars
}

var _ beaconing.Writer = (*RegistrarWriter)(nil)

func (w *RegistrarWriter) Write(
	ctx context.Context,
	beacons beacon.GroupedBeacons,
	peers []uint16,
) (beaconing.WriteStats, error) {
	logger := log.FromCtx(ctx)
	writeStats := beaconing.WriteStats{Count: 0, StartIAs: make(map[addr.IA]struct{})}
	for name, beacons := range beacons {
		registrar, err := w.Plugins.Get(w.PolicyType, name)
		if err != nil {
			return beaconing.WriteStats{}, serrors.Wrap("getting segment registrar", err,
				"policy", w.PolicyType, "name", name)
		}
		stats, err := registrar.RegisterSegments(ctx, beacons, peers)
		if err != nil {
			return beaconing.WriteStats{}, serrors.Wrap("registering segments", err,
				"policy", name)
		}
		// Log the segment-specific errors encountered during registration.
		for id, err := range stats.Status {
			if err != nil {
				logger.Error("Failed to register segment", "segment_id", id, "err", err)
			}
		}
		// Extend the write stats with the plugin-specific write stats.
		writeStats.Extend(stats.WriteStats)
	}
	return writeStats, nil
}

func (t *TasksConfig) segmentWriter(
	policyType beacon.PolicyType,
) *periodic.Runner {
	if t.registrars == nil {
		panic("segment registrars not initialized, call InitPlugins first")
	}
	segType, ok := SegmentTypeFromPolicyType(policyType)
	if !ok {
		panic(serrors.New("invalid policy type for segment writer",
			"policy_type", policyType))
	}
	r := &beaconing.WriteScheduler{
		Provider: t.BeaconStore,
		Intfs:    t.AllInterfaces,
		Type:     segType,
		Writer: &RegistrarWriter{
			PolicyType: policyType,
			Plugins:    t.registrars,
		},
		Tick: beaconing.NewTick(t.RegistrationInterval),
	}
	//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
	return periodic.Start(r, 500*time.Millisecond, t.RegistrationInterval)
}

func (t *TasksConfig) extender(
	task string,
	ia addr.IA,
	mtu uint16,
	maxExp func() uint8,
) beaconing.Extender {

	return &beaconing.DefaultExtender{
		IA:         ia,
		SignerGen:  t.SignerGen,
		MAC:        t.MACGen,
		Intfs:      t.AllInterfaces,
		MTU:        mtu,
		MaxExpTime: func() uint8 { return maxExp() },
		StaticInfo: t.StaticInfo,
		Task:       task,
		EPIC:       t.EPIC,
		SegmentExpirationDeficient: func() metrics.Gauge {
			if t.Metrics == nil {
				return nil
			}
			return metrics.NewPromGauge(t.Metrics.SegmentExpirationDeficient)
		}(),
	}
}

func (t *TasksConfig) DRKeyCleaners() []*periodic.Runner {
	if t.DRKeyEngine == nil {
		return nil
	}
	cleanerPeriod := 2 * t.DRKeyEpochInterval
	cleaners := t.DRKeyEngine.CreateStorageCleaners()
	cleanerTasks := make([]*periodic.Runner, len(cleaners))
	for i, cleaner := range cleaners {
		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		cleanerTasks[i] = periodic.Start(cleaner, cleanerPeriod, cleanerPeriod)
	}
	return cleanerTasks
}

func (t *TasksConfig) DRKeyPrefetcher() *periodic.Runner {
	if t.DRKeyEngine == nil {
		return nil
	}
	prefetchPeriod := t.DRKeyEpochInterval / 2
	//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
	return periodic.Start(
		&drkey.Prefetcher{
			LocalIA:     t.IA,
			Engine:      t.DRKeyEngine,
			KeyDuration: t.DRKeyEpochInterval,
		},
		prefetchPeriod,
		prefetchPeriod,
	)
}

// Tasks keeps track of the running tasks.
type Tasks struct {
	Originator      *periodic.Runner
	Propagator      *periodic.Runner
	Registrars      []*periodic.Runner
	DRKeyPrefetcher *periodic.Runner

	PathCleaner   *periodic.Runner
	DRKeyCleaners []*periodic.Runner
}

func StartTasks(cfg TasksConfig) (*Tasks, error) {

	segCleaner := pathdb.NewCleaner(cfg.PathDB, "control_pathstorage_segments")
	segRevCleaner := revcache.NewCleaner(cfg.RevCache, "control_pathstorage_revocation")
	return &Tasks{
		Originator: cfg.Originator(),
		Propagator: cfg.Propagator(),
		Registrars: cfg.SegmentWriters(),
		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		PathCleaner: periodic.Start(
			periodic.Func{
				Task: func(ctx context.Context) {
					segCleaner.Run(ctx)
					segRevCleaner.Run(ctx)
				},
				TaskName: "control_pathstorage_cleaner",
			},
			10*time.Second,
			10*time.Second,
		),
		DRKeyPrefetcher: cfg.DRKeyPrefetcher(),
		DRKeyCleaners:   cfg.DRKeyCleaners(),
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
		t.PathCleaner,
		t.DRKeyPrefetcher,
	})
	killRunners(t.Registrars)
	killRunners(t.DRKeyCleaners)
	t.Originator = nil
	t.Propagator = nil
	t.PathCleaner = nil
	t.Registrars = nil
	t.DRKeyPrefetcher = nil
	t.DRKeyCleaners = nil
}

func killRunners(runners []*periodic.Runner) {
	for _, r := range runners {
		r.Kill()
	}
}

// HiddenPathRegistrationCfg contains the required options to configure hidden
// paths down segment registration.
type HiddenPathRegistrationCfg struct {
	Policy     hiddenpath.RegistrationPolicy
	Router     snet.Router
	Discoverer hiddenpath.Discoverer
	RPC        hiddenpath.Register
}

// Store is the interface to interact with the beacon store.
type Store interface {
	// PreFilter indicates whether the beacon will be filtered on insert by
	// returning an error with the reason. This allows the caller to drop
	// ignored beacons.
	PreFilter(beacon beacon.Beacon) error
	// BeaconsToPropagate returns an error and an empty slice if an error (e.g., connection or
	// parsing error) occurs; otherwise, it returns a slice containing the beacons (which
	// potentially could be empty when no beacon is found) and no error.
	// The selection is based on the configured propagation policy.
	BeaconsToPropagate(ctx context.Context) ([]beacon.Beacon, error)
	// SegmentsToRegister returns an error and an empty slice if an error (e.g., connection or
	// parsing error) occurs; otherwise, it returns a slice containing the beacons (which
	// potentially could be empty when no beacon is found) and no error.
	// The selections is based on the configured propagation policy for the requested segment type.
	SegmentsToRegister(ctx context.Context, segType seg.Type) (beacon.GroupedBeacons, error)
	// InsertBeacon adds a verified beacon to the store, ignoring revocations.
	InsertBeacon(ctx context.Context, beacon beacon.Beacon) (beacon.InsertStats, error)
	// UpdatePolicy updates the policy. Beacons that are filtered by all
	// policies after the update are removed.
	UpdatePolicy(ctx context.Context, policy beacon.Policy) error
	// MaxExpTime returns the segment maximum expiration time for the given policy.
	MaxExpTime(policyType beacon.PolicyType) uint8
}
