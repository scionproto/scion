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

package beaconing

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/control/segreg"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/segment/seghandler"
	"github.com/scionproto/scion/private/topology"
)

// Pather computes the remote address with a path based on the provided segment.
type Pather interface {
	GetPath(svc addr.SVC, ps *seg.PathSegment) (net.Addr, error)
}

// SegmentProvider provides segments to register for the specified type.
type SegmentProvider interface {
	// SegmentsToRegister returns the segments that should be registered for the
	// given segment type as GroupedBeacons.
	// The returned GroupedBeacons must not be nil if the returned error is nil.
	SegmentsToRegister(ctx context.Context, segType seg.Type) (beacon.GroupedBeacons, error)
}

// SegmentStore stores segments in the path database.
type SegmentStore interface {
	StoreSegs(context.Context, []*seg.Meta) (seghandler.SegStats, error)
}

// RPC registers the path segment with the remote.
type RPC interface {
	RegisterSegment(ctx context.Context, meta seg.Meta, remote net.Addr) error
}

// WriteStats provides statistics about segment writing.
type WriteStats struct {
	// Count is the number of successfully written segments.
	Count int
	// StartIAs lists the AS.
	StartIAs map[addr.IA]struct{}
}

// Extend extends the current WriteStats with another WriteStats.
func (s *WriteStats) Extend(other WriteStats) {
	if s.StartIAs == nil {
		s.StartIAs = make(map[addr.IA]struct{})
	}
	s.Count += other.Count
	for ia := range other.StartIAs {
		s.StartIAs[ia] = struct{}{}
	}
}

// Writer writes segments.
type Writer interface {
	// Write writes passed segments. Peers indicate the peering interface IDs
	// of the local IA. The returned statistics should provide insights about
	// how many segments have been successfully written. The method should return
	// an error if the writing did fail.
	Write(ctx context.Context, beacons beacon.GroupedBeacons, peers []uint16) (WriteStats, error)
}

var _ periodic.Task = (*WriteScheduler)(nil)

// WriteScheduler is used to periodically write path segments at the configured
// writer.
type WriteScheduler struct {
	// Provider is used to query for segments.
	Provider SegmentProvider
	// Intfs gives access to the interfaces this CS beacons over.
	Intfs *ifstate.Interfaces
	// Type is the type of segments that should be queried from the Provider.
	Type seg.Type
	// Write is used to write the segments once the scheduling determines it is
	// time to write.
	Writer Writer

	// Tick is mutable. It's used to determine when to call write.
	Tick Tick
	// lastWrite indicates the time of the last successful write.
	lastWrite time.Time
}

// Name returns the tasks name.
func (r *WriteScheduler) Name() string {
	// XXX(lukedirtwalker): this name is used in metrics and changing it would
	// be a breaking change.
	return "control_beaconing_registrar"
}

// Run writes path segments using the configured writer.
func (r *WriteScheduler) Run(ctx context.Context) {
	r.Tick.SetNow(time.Now())
	if err := r.run(ctx); err != nil {
		log.FromCtx(ctx).Error("Unable to register", "seg_type", r.Type, "err", err)
	}
	r.Tick.UpdateLast()
}

func (r *WriteScheduler) run(ctx context.Context) error {
	if !r.Tick.Overdue(r.lastWrite) && !r.Tick.Passed() {
		return nil
	}
	segments, err := r.Provider.SegmentsToRegister(ctx, r.Type)
	if err != nil {
		return err
	}
	peers := sortedIntfs(r.Intfs, topology.Peer)
	stats, err := r.Writer.Write(ctx, segments, peers)
	if err != nil {
		return err
	}
	r.logSummary(ctx, &summary{count: stats.Count, srcs: stats.StartIAs})
	if stats.Count > 0 {
		r.lastWrite = r.Tick.Now()
	}
	return err
}

func (r *WriteScheduler) logSummary(ctx context.Context, s *summary) {
	logger := log.FromCtx(ctx)
	if r.Tick.Passed() {
		logger.Debug("Registered beacons", "seg_type", r.Type, "count", s.count,
			"start_isd_ases", len(s.srcs))
		return
	}
	if s.count > 0 {
		logger.Debug("Registered beacons after stale period",
			"seg_type", r.Type, "count", s.count, "start_isd_ases", len(s.srcs))
	}
}

type LocalSegmentRegistrationPlugin struct {
	// InternalErrors counts errors that happened before being able to store
	// a segment in the local SegmentStore.
	InternalErrors func(segType string) metrics.Counter
	// Registered counts the amount of registered segments. A label is used to
	// indicate the status of the registration.
	Registered func(startIA addr.IA, ingress uint16, segType string, result string) metrics.Counter
	// Store is used to store the terminated segments.
	Store SegmentStore
}

var _ segreg.SegmentRegistrationPlugin = (*LocalSegmentRegistrationPlugin)(nil)

func (p *LocalSegmentRegistrationPlugin) ID() string {
	return "local"
}

func (p *LocalSegmentRegistrationPlugin) Validate(config map[string]any) error {
	// Local segment registration does not require any specific configuration.
	return nil
}

func (p *LocalSegmentRegistrationPlugin) New(
	ctx context.Context,
	policyType beacon.RegPolicyType,
	config map[string]any,
) (segreg.SegmentRegistrar, error) {
	segType := policyType.SegmentType()
	var internalErrors metrics.Counter
	if p.InternalErrors != nil {
		internalErrors = p.InternalErrors(segType.String())
	}
	return &LocalWriter{
		LocalSegmentRegistrationPlugin: *p,
		InternalErrors:                 internalErrors,
		Type:                           segType,
	}, nil
}

// LocalWriter can be used to write segments in the local SegmentStore.
type LocalWriter struct {
	LocalSegmentRegistrationPlugin
	// InternalErrors counts errors that happened before being able to store
	// a segment in the local SegmentStore (with the segment type label).
	InternalErrors metrics.Counter
	// Type is the type of segment that is handled by this writer.
	Type seg.Type
}

var _ segreg.SegmentRegistrar = (*LocalWriter)(nil)

// RegisterSegments registers the segments in the local SegmentStore.
func (r *LocalWriter) RegisterSegments(
	ctx context.Context,
	beacons []beacon.Beacon,
	peers []uint16,
) *segreg.RegistrationSummary {
	if len(beacons) < 1 {
		// Nothing to register.
		return nil
	}

	logger := log.FromCtx(ctx)

	// beacons keyed with their logging ID.
	logBeacons := make(map[string]beacon.Beacon)
	var toRegister []*seg.Meta
	for _, b := range beacons {
		toRegister = append(toRegister, &seg.Meta{Type: r.Type, Segment: b.Segment})
		logBeacons[b.Segment.GetLoggingID()] = b
	}
	stats, err := r.Store.StoreSegs(ctx, toRegister)
	// If an error occurred while storing, no segments were registered, since StoreSegs
	// does a batch insert. As a result, we report every segment failing with the returned error.
	if err != nil {
		metrics.CounterInc(r.InternalErrors)
		logger.Error("Unable to register segments", "err", err, "count", len(toRegister))
		return nil
	}
	r.updateMetricsFromStats(stats, logBeacons)
	return segreg.SummarizeSegStats(stats, logBeacons)
}

// updateMetricsFromStat is used to update the metrics for local DB inserts.
func (r *LocalWriter) updateMetricsFromStats(s seghandler.SegStats, b map[string]beacon.Beacon) {
	if r.Registered == nil {
		return
	}
	for _, id := range s.InsertedSegs {
		metrics.CounterInc(r.Registered(
			b[id].Segment.FirstIA(),
			b[id].InIfID,
			r.Type.String(),
			"ok_new",
		))
	}
	for _, id := range s.UpdatedSegs {
		metrics.CounterInc(r.Registered(
			b[id].Segment.FirstIA(),
			b[id].InIfID,
			r.Type.String(),
			"ok_updated",
		))
	}
}

type RemoteSegmentRegistrationPlugin struct {
	// InternalErrors counts errors that happened before being able to send a
	// segment to a remote. This can be during looking up the remote etc.
	// If the counter is nil errors are not counted.
	InternalErrors func(segType string) metrics.Counter
	// Registered counts the amount of registered segments. A label is used to
	// indicate the status of the segreg.
	Registered func(startIA addr.IA, ingress uint16, segType string, result string) metrics.Counter

	// RPC is used to send the segment to a remote.
	RPC RPC
	// Pather is used to construct paths to the originator of a beacon.
	Pather Pather
}

var _ segreg.SegmentRegistrationPlugin = (*RemoteSegmentRegistrationPlugin)(nil)

func (p *RemoteSegmentRegistrationPlugin) ID() string {
	return "remote"
}

func (p *RemoteSegmentRegistrationPlugin) Validate(config map[string]any) error {
	// Local segment registration does not require any specific configuration.
	return nil
}

func (p *RemoteSegmentRegistrationPlugin) New(
	ctx context.Context,
	policyType beacon.RegPolicyType,
	config map[string]any,
) (segreg.SegmentRegistrar, error) {
	segType := policyType.SegmentType()
	var internalErrors metrics.Counter
	if p.InternalErrors != nil {
		internalErrors = p.InternalErrors(segType.String())
	}
	return &RemoteWriter{
		RemoteSegmentRegistrationPlugin: *p,
		InternalErrors:                  internalErrors,
		Type:                            segType,
	}, nil
}

// RemoteWriter writes segments via an RPC to the source AS of a segment.
type RemoteWriter struct {
	RemoteSegmentRegistrationPlugin
	// InternalErrors counts errors that happened before being able to send a
	// segment to a remote (with the segment type label).
	InternalErrors metrics.Counter
	// Type is the type of segment that is handled by this writer.
	Type seg.Type
}

var _ segreg.SegmentRegistrar = (*RemoteWriter)(nil)

// RegisterSegments writes the segment at the source AS of the segment.
func (r *RemoteWriter) RegisterSegments(
	ctx context.Context,
	beacons []beacon.Beacon,
	peers []uint16,
) *segreg.RegistrationSummary {
	logger := log.FromCtx(ctx)

	summary := segreg.NewSummary()
	var wg sync.WaitGroup

	for _, b := range beacons {
		s := remoteWriter{
			writer:  r,
			rpc:     r.RPC,
			summary: summary,
			wg:      &wg,
			pather:  r.Pather,
		}

		// Avoid head-of-line blocking when sending message to slow servers.
		s.start(ctx, b)
	}
	wg.Wait()
	if len(beacons) > 0 && summary.GetCount() <= 0 {
		logger.Error("No beacons registered", "candidates", len(beacons))
		return nil
	}
	return summary
}

// remoteWriter registers one segment with the path server.
type remoteWriter struct {
	writer  *RemoteWriter
	rpc     RPC
	pather  Pather
	summary *segreg.RegistrationSummary
	wg      *sync.WaitGroup
}

// start extends the beacon and starts a go routine that registers the beacon
// with the path server.
//
// If an error occurs, it is logged, the internal error counter is incremented,
// and the status map is updated.
func (r *remoteWriter) start(ctx context.Context, bseg beacon.Beacon) {
	logger := log.FromCtx(ctx)
	addr, err := r.pather.GetPath(addr.SvcCS, bseg.Segment)
	if err != nil {
		logger.Error("Unable to choose server", "err", err)
		metrics.CounterInc(r.writer.InternalErrors)
		return
	}
	r.startSendSegReg(ctx, bseg, seg.Meta{Type: r.writer.Type, Segment: bseg.Segment}, addr)
}

// startSendSegReg adds to the wait group and starts a goroutine that sends the
// registration message to the peer.
func (r *remoteWriter) startSendSegReg(
	ctx context.Context,
	bseg beacon.Beacon,
	reg seg.Meta,
	addr net.Addr,
) {

	r.wg.Add(1)
	go func() {
		defer log.HandlePanic()
		defer r.wg.Done()

		logger := log.FromCtx(ctx)
		if err := r.rpc.RegisterSegment(ctx, reg, addr); err != nil {
			logger.Error("Unable to register segment",
				"seg_type", r.writer.Type, "addr", addr, "err", err)
			if r.writer.Registered != nil {
				metrics.CounterInc(r.writer.Registered(
					bseg.Segment.FirstIA(),
					bseg.InIfID,
					r.writer.Type.String(),
					prom.ErrNetwork,
				))
			}
			return
		}
		r.summary.RecordSegment(bseg.Segment)
		if r.writer.Registered != nil {
			metrics.CounterInc(r.writer.Registered(
				bseg.Segment.FirstIA(),
				bseg.InIfID,
				r.writer.Type.String(),
				prom.Success,
			))
		}
		logger.Debug("Successfully registered segment", "seg_type", r.writer.Type,
			"addr", addr, "seg", bseg.Segment)
	}()
}

// GroupWriter is a beaconing.Writer that terminates and writes beacons across multiple segment
// registrars registered in Plugins. It is parameterized by a PolicyType, which determines the
// registrars that will be used.
type GroupWriter struct {
	PolicyType beacon.RegPolicyType
	// Registrars is used to get the segment registrars for the PolicyType.
	Registrars segreg.SegmentRegistrars
	// Intfs is used to filter out beacons that do not have a valid interface ID.
	// If Intfs is nil, no filtering is done.
	Intfs *ifstate.Interfaces
	// Extender is used to terminate the segments of the beacons before registering them.
	// If Extender is nil, no termination is done.
	Extender Extender
	// InternalErrors counts the errors during segment termination.
	// If the counter is nil, errors are not counted.
	InternalErrors metrics.Counter
}

var _ Writer = (*GroupWriter)(nil)

// processSegments processes the segments by terminating them and filtering out
// the segments that do not have a valid interface ID.
func (w *GroupWriter) processSegments(
	ctx context.Context,
	beacons beacon.GroupedBeacons,
	peers []uint16,
) beacon.GroupedBeacons {
	logger := log.FromCtx(ctx)
	processed := make(beacon.GroupedBeacons, len(beacons))
	for group, beacons := range beacons {
		processedGroup := make([]beacon.Beacon, 0, len(beacons))
		for _, b := range beacons {
			// If the beacon does not have a valid interface ID, skip it.
			if w.Intfs != nil && w.Intfs.Get(b.InIfID) == nil {
				continue
			}
			// Try to terminate the segment if an extender is configured.
			if w.Extender != nil {
				err := w.Extender.Extend(ctx, b.Segment, b.InIfID, 0, peers)
				if err != nil {
					logger.Error("Unable to terminate beacon", "beacon", b, "err", err)
					metrics.CounterInc(w.InternalErrors)
					continue
				}
			}
			processedGroup = append(processedGroup, b)
		}
		if len(processedGroup) > 0 {
			processed[group] = processedGroup
		}
	}
	return processed
}

// Write writes beacons to multiple segment registrars based on the PolicyType.
//
// For every group of beacons, the correct registrar is selected based on the PolicyType
// and the group's name (which should correspond to the registration policy name).
func (w *GroupWriter) Write(
	ctx context.Context,
	allBeacons beacon.GroupedBeacons,
	peers []uint16,
) (WriteStats, error) {
	processedBeacons := w.processSegments(ctx, allBeacons, peers)
	writeStats := WriteStats{Count: 0, StartIAs: make(map[addr.IA]struct{})}
	// Defines a concurrent task, i.e., registration of a group of segments with a
	// specific registrar.
	type task struct {
		Beacons []beacon.Beacon
		Reg     segreg.SegmentRegistrar
	}
	tasks := make([]task, 0, len(processedBeacons))
	// Collect the registrars and the beacons that should be registered with them as tasks.
	for name, beacons := range processedBeacons {
		registrar, err := w.Registrars.GetSegmentRegistrar(w.PolicyType, name)
		if err != nil {
			return WriteStats{}, serrors.Wrap("getting segment registrar", err,
				"policy", w.PolicyType, "name", name)
		}
		tasks = append(tasks, task{Beacons: beacons, Reg: registrar})
	}
	// Run the tasks concurrently and collect the write stats.
	allWriteStats := make([]WriteStats, len(tasks))
	wg := sync.WaitGroup{}
	wg.Add(len(tasks))
	for i, task := range tasks {
		go func(j int) {
			defer wg.Done()
			sum := task.Reg.RegisterSegments(ctx, task.Beacons, peers)
			if sum == nil {
				return
			}
			allWriteStats[j] = WriteStats{
				Count:    sum.GetCount(),
				StartIAs: sum.GetSrcs(),
			}
		}(i)
	}
	wg.Wait()
	// Extend the write stats with the results from all registrars.
	for _, stats := range allWriteStats {
		writeStats.Extend(stats)
	}
	return writeStats, nil
}
