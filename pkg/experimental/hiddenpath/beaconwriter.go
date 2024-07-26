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

package hiddenpath

import (
	"context"
	"net"
	"strconv"
	"sync"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
)

// SegmentRegistration is a registration for hidden segments.
type SegmentRegistration struct {
	GroupID GroupID
	Seg     seg.Meta
}

// Register is used to register segments to a remote.
type Register interface {
	RegisterSegment(context.Context, SegmentRegistration, net.Addr) error
}

// BeaconWriter terminates segments and registers them at remotes. The remotes
// can either be a public core segment registry or a hidden segment registry.
type BeaconWriter struct {
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
	Extender beaconing.Extender
	// RPC is used to send the segment to the remote. For public registrations
	// the entry with an empty group ID as key is used.
	RPC Register
	// Pather is used to construct paths to the originator of a beacon.
	Pather beaconing.Pather
	// RegistrationPolicy is the hidden path registration policy.
	RegistrationPolicy RegistrationPolicy
	// AddressResolver is used to resolve remote ASes.
	AddressResolver AddressResolver
}

// Write iterates the segments channel and for each of the segments: it extends
// it, it finds the remotes via the registration policy, it finds a path for
// each remote, it sends the segment via the found path. Peers are the peer
// interfaces in this AS.
func (w *BeaconWriter) Write(ctx context.Context, segments []beacon.Beacon,
	peers []uint16) (beaconing.WriteStats, error) {

	logger := log.FromCtx(ctx)
	summary := newSummary()
	var expected int
	var wg sync.WaitGroup

	for _, b := range segments {
		if w.Intfs.Get(b.InIfID) == nil {
			logger.Error("Received beacon for non-existing interface", "interface", b.InIfID)
			metrics.CounterInc(w.InternalErrors)
			continue
		}
		regPolicy, ok := w.RegistrationPolicy[uint64(b.InIfID)]
		if !ok {
			logger.Info("no HP nor public registration policy for beacon", "interface", b.InIfID)
			continue
		}
		err := w.Extender.Extend(ctx, b.Segment, b.InIfID, 0, peers)
		if err != nil {
			logger.Error("Unable to terminate beacon", "beacon", b, "err", err)
			metrics.CounterInc(w.InternalErrors)
			continue
		}
		for id, addrs := range remoteRegistries(regPolicy) {
			for _, a := range addrs {
				expected++
				rw := remoteWriter{
					internalErrors:  w.InternalErrors,
					registered:      w.Registered,
					summary:         summary,
					hiddenPathGroup: id,
					resolveRemote: func(ctx context.Context) (net.Addr, error) {
						return w.AddressResolver.Resolve(ctx, a)
					},
					rpc: w.RPC,
				}
				if id.ToUint64() == 0 {
					// public
					seg := b.Segment
					rw.resolveRemote = func(_ context.Context) (net.Addr, error) {
						return w.Pather.GetPath(addr.SvcCS, seg)
					}
				}
				wg.Add(1)
				go func(bseg beacon.Beacon) {
					defer log.HandlePanic()
					defer wg.Done()
					rw.run(ctx, bseg)
				}(b)
			}
		}
	}

	wg.Wait()
	if expected > 0 && summary.count <= 0 {
		return beaconing.WriteStats{}, serrors.New("no beacons registered", "candidates", expected)
	}
	return beaconing.WriteStats{Count: summary.count, StartIAs: summary.srcs}, nil
}

// remoteWriter registers one segment with the path server.
type remoteWriter struct {
	internalErrors  metrics.Counter
	registered      metrics.Counter
	summary         *summary
	hiddenPathGroup GroupID
	resolveRemote   func(context.Context) (net.Addr, error)
	rpc             Register
}

// run resolves, and writes the segment to the remote registry.
func (w *remoteWriter) run(ctx context.Context, bseg beacon.Beacon) {
	reg := SegmentRegistration{
		Seg:     seg.Meta{Type: seg.TypeDown, Segment: bseg.Segment},
		GroupID: w.hiddenPathGroup,
	}

	logger := log.FromCtx(ctx)

	addr, err := w.resolveRemote(ctx)
	if err != nil {
		logger.Error("Unable to choose server", "hp_group", w.hpGroup(), "err", err)
		metrics.CounterInc(w.internalErrors)
		return
	}

	labels := writerLabels{
		StartIA: bseg.Segment.FirstIA(),
		Ingress: bseg.InIfID,
		SegType: w.segTypeString(),
	}

	if err := w.rpc.RegisterSegment(ctx, reg, addr); err != nil {
		logger.Error("Unable to register segment",
			"seg_type", w.segTypeString(), "addr", addr, "hp_group", w.hpGroup(), "err", err)
		metrics.CounterInc(metrics.CounterWith(w.registered,
			labels.WithResult(prom.ErrNetwork).Expand()...))
		return
	}
	w.summary.AddSrc(bseg.Segment.FirstIA())
	w.summary.Inc()

	metrics.CounterInc(metrics.CounterWith(w.registered,
		labels.WithResult(prom.Success).Expand()...))
	logger.Debug("Successfully registered segment", "seg_type", w.segTypeString(),
		"addr", addr, "seg", bseg.Segment, "hp_group", w.hpGroup())
}

func (w *remoteWriter) hpGroup() string {
	if w.hiddenPathGroup.ToUint64() != 0 {
		return w.hiddenPathGroup.String()
	}
	return "public"
}

func (w *remoteWriter) segTypeString() string {
	s := seg.TypeDown.String()
	if w.hiddenPathGroup.ToUint64() != 0 {
		s = "hidden_" + s
	}
	return s
}

type summary struct {
	mu    sync.Mutex
	srcs  map[addr.IA]struct{}
	count int
}

func newSummary() *summary {
	return &summary{
		srcs: make(map[addr.IA]struct{}),
	}
}

func (s *summary) AddSrc(ia addr.IA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.srcs[ia] = struct{}{}
}

func (s *summary) Inc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
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

func remoteRegistries(regPolicy InterfacePolicy) map[GroupID][]addr.IA {
	remotes := make(map[GroupID][]addr.IA)
	for id, group := range regPolicy.Groups {
		for registry := range group.Registries {
			remotes[id] = append(remotes[id], registry)
		}
	}
	if regPolicy.Public {
		remotes[GroupID{}] = []addr.IA{0}
	}
	return remotes
}
