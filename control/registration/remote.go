// Copyright 2025 Anapaya Systems
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

package registration

import (
	"context"
	"net"
	"sync"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
)

type RemoteSegmentRegistrationPlugin struct {
	// InternalErrors counts errors that happened before being able to send a
	// segment to a remote. This can be during looking up the remote etc.
	// If the counter is nil errors are not counted.
	InternalErrors metrics.Counter
	// Registered counts the amount of registered segments. A label is used to
	// indicate the status of the registration.
	Registered metrics.Counter

	// RPC is used to send the segment to a remote.
	RPC beaconing.RPC
	// Pather is used to construct paths to the originator of a beacon.
	Pather beaconing.Pather
}

var _ SegmentRegistrationPlugin = (*RemoteSegmentRegistrationPlugin)(nil)

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
) (SegmentRegistrar, error) {
	segType := policyType.SegmentType()
	return &RemoteSegmentRegistrar{
		RemoteSegmentRegistrationPlugin: *p,
		InternalErrors: metrics.CounterWith(
			p.InternalErrors,
			"seg_type", segType.String(),
		),
		Type: segType,
	}, nil
}

// RemoteSegmentRegistrar writes segments via an RPC to the source AS of a segment.
type RemoteSegmentRegistrar struct {
	RemoteSegmentRegistrationPlugin
	InternalErrors metrics.Counter
	// Type is the type of segment that is handled by this writer.
	Type seg.Type
}

var _ SegmentRegistrar = (*RemoteSegmentRegistrar)(nil)

// RegisterSegments writes the segment at the source AS of the segment.
func (r *RemoteSegmentRegistrar) RegisterSegments(
	ctx context.Context,
	beacons []beacon.Beacon,
	peers []uint16,
) (RegistrationStats, error) {
	s := newSummary()
	var expected int
	var wg sync.WaitGroup

	// Segment-specific errors.
	status := make(map[string]error)

	for _, b := range beacons {
		expected++
		s := remoteWriter{
			writer:  r,
			rpc:     r.RPC,
			summary: s,
			wg:      &wg,
			pather:  r.Pather,
		}

		// Avoid head-of-line blocking when sending message to slow servers.
		s.start(ctx, b, status)
	}
	wg.Wait()
	if expected > 0 && s.count <= 0 {
		return RegistrationStats{}, serrors.New("no beacons registered", "candidates", expected)
	}
	return RegistrationStats{
		WriteStats: beaconing.WriteStats{
			Count:    s.count,
			StartIAs: s.srcs,
		},
		Status: status,
	}, nil
}

// remoteWriter registers one segment with the path server.
type remoteWriter struct {
	writer  *RemoteSegmentRegistrar
	rpc     beaconing.RPC
	pather  beaconing.Pather
	summary *summary
	wg      *sync.WaitGroup
}

// start extends the beacon and starts a go routine that registers the beacon
// with the path server.
//
// If an error occurs, it is logged, the internal error counter is incremented,
// and the status map is updated.
func (r *remoteWriter) start(ctx context.Context, bseg beacon.Beacon, status map[string]error) {
	logger := log.FromCtx(ctx)
	addr, err := r.pather.GetPath(addr.SvcCS, bseg.Segment)
	if err != nil {
		logger.Error("Unable to choose server", "err", err)
		metrics.CounterInc(r.writer.InternalErrors)
		status[string(bseg.Segment.FullID())] = err
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
