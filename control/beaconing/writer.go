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
	"strconv"
	"sync"
	"time"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/segment/seghandler"
	"github.com/scionproto/scion/private/topology"
)

// Pather computes the remote address with a path based on the provided segment.
type Pather interface {
	GetPath(svc addr.SVC, ps *seg.PathSegment) (*snet.SVCAddr, error)
}

// SegmentProvider provides segments to register for the specified type.
type SegmentProvider interface {
	// SegmentsToRegister returns the segments that should be registered for the
	// given segment type. The returned slice must not be nil if the returned
	// error is nil.
	SegmentsToRegister(ctx context.Context, segType seg.Type) ([]beacon.Beacon, error)
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

// Writer writes segments.
type Writer interface {
	// Write writes passed slice of segments.Peers indicate the peering
	// interface IDs of the local IA. The returned statistics should provide
	// insights about how many segments have been successfully written. The
	// method should return an error if the writing did fail.
	Write(ctx context.Context, segs []beacon.Beacon, peers []uint16) (WriteStats, error)
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
	if !(r.Tick.Overdue(r.lastWrite) || r.Tick.Passed()) {
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

// RemoteWriter writes segments via an RPC to the source AS of a segment.
type RemoteWriter struct {
	// InternalErrors counts errors that happened before being able to send a
	// segment to a remote. This can be during terminating the segment, looking
	// up the remote etc. If the counter is nil errors are not counted.
	InternalErrors metrics.Counter
	// Registered counts the amount of registered segments. A label is used to
	// indicate the status of the registration.
	Registered metrics.Counter
	// Intfs gives access to the interfaces this CS beacons over.
	Intfs *ifstate.Interfaces
	// Extender is used to terminate the beacon.
	Extender Extender
	// Type is the type of segment that is handled by this writer.
	Type seg.Type
	// RPC is used to send the segment to a remote.
	RPC RPC
	// Pather is used to find paths to a remote.
	Pather Pather
}

// Write writes the segment at the source AS of the segment.
func (r *RemoteWriter) Write(
	ctx context.Context,
	segments []beacon.Beacon,
	peers []uint16,
) (WriteStats, error) {

	logger := log.FromCtx(ctx)
	s := newSummary()
	var expected int
	var wg sync.WaitGroup
	for _, b := range segments {
		if r.Intfs.Get(b.InIfID) == nil {
			continue
		}
		err := r.Extender.Extend(ctx, b.Segment, b.InIfID, 0, peers)
		if err != nil {
			logger.Error("Unable to terminate beacon", "beacon", b, "err", err)
			metrics.CounterInc(r.InternalErrors)
			continue
		}
		expected++
		s := remoteWriter{
			writer:  r,
			rpc:     r.RPC,
			pather:  r.Pather,
			summary: s,
			wg:      &wg,
		}

		// Avoid head-of-line blocking when sending message to slow servers.
		s.start(ctx, b)
	}
	wg.Wait()
	if expected > 0 && s.count <= 0 {
		return WriteStats{}, serrors.New("no beacons registered", "candidates", expected)
	}
	return WriteStats{Count: s.count, StartIAs: s.srcs}, nil
}

// LocalWriter can be used to write segments in the SegmentStore.
type LocalWriter struct {
	// InternalErrors counts errors that happened before being able to send a
	// segment to a remote. This can for example be during the termination of
	// the segment. If the counter is nil errors are not counted.
	InternalErrors metrics.Counter
	// Registered counts the amount of registered segments. A label is used to
	// indicate the status of the registration.
	Registered metrics.Counter
	// Type is the type of segment that is handled by this writer.
	Type seg.Type
	// Store is used to store the terminated segments.
	Store SegmentStore
	// Extender is used to terminate the beacon.
	Extender Extender
	// Intfs gives access to the interfaces this CS beacons over.
	Intfs *ifstate.Interfaces
}

// Write terminates the segments and registers them in the SegmentStore.
func (r *LocalWriter) Write(
	ctx context.Context,
	segments []beacon.Beacon,
	peers []uint16,
) (WriteStats, error) {

	logger := log.FromCtx(ctx)
	beacons := make(map[string]beacon.Beacon)
	var toRegister []*seg.Meta
	for _, b := range segments {
		if r.Intfs.Get(b.InIfID) == nil {
			continue
		}
		err := r.Extender.Extend(ctx, b.Segment, b.InIfID, 0, peers)
		if err != nil {
			logger.Error("Unable to terminate beacon", "beacon", b, "err", err)
			metrics.CounterInc(r.InternalErrors)
			continue
		}
		toRegister = append(toRegister, &seg.Meta{Type: r.Type, Segment: b.Segment})
		beacons[b.Segment.GetLoggingID()] = b
	}
	if len(toRegister) == 0 {
		return WriteStats{}, nil
	}
	stats, err := r.Store.StoreSegs(ctx, toRegister)
	if err != nil {
		metrics.CounterInc(r.InternalErrors)
		return WriteStats{}, err
	}
	r.updateMetricsFromStat(stats, beacons)
	sum := summarizeStats(stats, beacons)
	return WriteStats{Count: sum.count, StartIAs: sum.srcs}, nil
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

// updateMetricsFromStat is used to update the metrics for local DB inserts.
func (r *LocalWriter) updateMetricsFromStat(s seghandler.SegStats, b map[string]beacon.Beacon) {
	for _, id := range s.InsertedSegs {
		metrics.CounterInc(metrics.CounterWith(r.Registered, writerLabels{
			StartIA: b[id].Segment.FirstIA(),
			Ingress: b[id].InIfID,
			SegType: r.Type.String(),
			Result:  "ok_new",
		}.Expand()...))
	}
	for _, id := range s.UpdatedSegs {
		metrics.CounterInc(metrics.CounterWith(r.Registered, writerLabels{
			StartIA: b[id].Segment.FirstIA(),
			Ingress: b[id].InIfID,
			SegType: r.Type.String(),
			Result:  "ok_updated",
		}.Expand()...))
	}
}

// remoteWriter registers one segment with the path server.
type remoteWriter struct {
	writer  *RemoteWriter
	rpc     RPC
	pather  Pather
	summary *summary
	wg      *sync.WaitGroup
}

// start extends the beacon and starts a go routine that registers the beacon
// with the path server.
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
func (r *remoteWriter) startSendSegReg(ctx context.Context, bseg beacon.Beacon,
	reg seg.Meta, addr net.Addr) {

	r.wg.Add(1)
	go func() {
		defer log.HandlePanic()
		defer r.wg.Done()

		labels := writerLabels{
			StartIA: bseg.Segment.FirstIA(),
			Ingress: bseg.InIfID,
			SegType: r.writer.Type.String(),
		}

		logger := log.FromCtx(ctx)
		if err := r.rpc.RegisterSegment(ctx, reg, addr); err != nil {
			logger.Error("Unable to register segment",
				"seg_type", r.writer.Type, "addr", addr, "err", err)
			metrics.CounterInc(metrics.CounterWith(r.writer.Registered,
				labels.WithResult(prom.ErrNetwork).Expand()...))
			return
		}
		r.summary.AddSrc(bseg.Segment.FirstIA())
		r.summary.Inc()

		metrics.CounterInc(metrics.CounterWith(r.writer.Registered,
			labels.WithResult(prom.Success).Expand()...))
		logger.Debug("Successfully registered segment", "seg_type", r.writer.Type,
			"addr", addr, "seg", bseg.Segment)
	}()
}

func summarizeStats(s seghandler.SegStats, b map[string]beacon.Beacon) *summary {
	sum := newSummary()
	for _, id := range append(s.InsertedSegs, s.UpdatedSegs...) {
		sum.AddSrc(b[id].Segment.FirstIA())
		sum.Inc()
	}
	return sum
}

type writerLabels struct {
	StartIA addr.IA
	Ingress uint16
	SegType string
	Result  string
}

func (l writerLabels) Expand() []string {
	return []string{
		"start_isd_as", l.StartIA.String(),
		"ingress_interface", strconv.Itoa(int(l.Ingress)),
		"seg_type", l.SegType,
		prom.LabelResult, l.Result,
	}
}

func (l writerLabels) WithResult(result string) writerLabels {
	l.Result = result
	return l
}
