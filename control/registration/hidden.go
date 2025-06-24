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
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet/addrutil"
)

type HiddenPathRegistrationPlugin struct{}

var _ SegmentRegistrationPlugin = (*HiddenPathRegistrationPlugin)(nil)

func (p *HiddenPathRegistrationPlugin) ID() string {
	return "hidden_path"
}

func (p *HiddenPathRegistrationPlugin) Validate(config map[string]any) error {
	return nil
}

func (p *HiddenPathRegistrationPlugin) New(
	ctx context.Context,
	pc PluginConstructor,
	segType seg.Type,
	policyType beacon.PolicyType,
	config map[string]any,
) (SegmentRegistrar, error) {
	if segType != seg.TypeDown {
		return nil, serrors.New("hidden path registration only supports down segments")
	}
	if pc.HiddenPathRPC == nil {
		return nil, serrors.New("hidden path RPC is not configured")
	}
	return &HiddenPathWriter{
		RPC:                pc.HiddenPathRPC,
		InternalErrors:     pc.InternalErrors,
		Registered:         pc.Registered,
		RegistrationPolicy: pc.HiddenPathRegPolicy,
		Pather: addrutil.Pather{
			NextHopper: pc.NextHopper,
		},
		AddressResolver: pc.HiddenPathResolver,
	}, nil
}

type HiddenPathWriter struct {
	InternalErrors     metrics.Counter
	Registered         metrics.Counter
	RegistrationPolicy hiddenpath.RegistrationPolicy
	Pather             addrutil.Pather
	AddressResolver    hiddenpath.AddressResolver
	RPC                hiddenpath.Register
}

var _ SegmentRegistrar = (*HiddenPathWriter)(nil)

// Write iterates the segments channel and for each of the segments: it extends
// it, it finds the remotes via the registration policy, it finds a path for
// each remote, it sends the segment via the found path. Peers are the peer
// interfaces in this AS.
//
// Only beacons[beacon.DEFAULT_GROUP] are considered.
func (w *HiddenPathWriter) RegisterSegments(
	ctx context.Context,
	beacons []beacon.Beacon,
	peers []uint16,
) (RegistrationStats, error) {

	logger := log.FromCtx(ctx)
	summary := newSummary()
	var expected int
	var wg sync.WaitGroup

	for _, b := range beacons {
		regPolicy, ok := w.RegistrationPolicy[uint64(b.InIfID)]
		if !ok {
			logger.Info("no HP nor public registration policy for beacon", "interface", b.InIfID)
			continue
		}
		for id, addrs := range remoteRegistries(regPolicy) {
			for _, a := range addrs {
				expected++
				rw := hiddenPathRemoteWriter{
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
		return RegistrationStats{}, serrors.New("no beacons registered", "candidates", expected)
	}
	return RegistrationStats{
		WriteStats: beaconing.WriteStats{Count: summary.count, StartIAs: summary.srcs},
	}, nil
}

// hiddenPathRemoteWriter registers one segment with the path server.
type hiddenPathRemoteWriter struct {
	internalErrors  metrics.Counter
	registered      metrics.Counter
	summary         *summary
	hiddenPathGroup hiddenpath.GroupID
	resolveRemote   func(context.Context) (net.Addr, error)
	rpc             hiddenpath.Register
}

// run resolves, and writes the segment to the remote registry.
func (w *hiddenPathRemoteWriter) run(ctx context.Context, bseg beacon.Beacon) {
	reg := hiddenpath.SegmentRegistration{
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

func (w *hiddenPathRemoteWriter) hpGroup() string {
	if w.hiddenPathGroup.ToUint64() != 0 {
		return w.hiddenPathGroup.String()
	}
	return "public"
}

func (w *hiddenPathRemoteWriter) segTypeString() string {
	s := seg.TypeDown.String()
	if w.hiddenPathGroup.ToUint64() != 0 {
		s = "hidden_" + s
	}
	return s
}

func remoteRegistries(regPolicy hiddenpath.InterfacePolicy) map[hiddenpath.GroupID][]addr.IA {
	remotes := make(map[hiddenpath.GroupID][]addr.IA)
	for id, group := range regPolicy.Groups {
		for registry := range group.Registries {
			remotes[id] = append(remotes[id], registry)
		}
	}
	if regPolicy.Public {
		remotes[hiddenpath.GroupID{}] = []addr.IA{0}
	}
	return remotes
}
