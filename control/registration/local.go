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

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/segment/seghandler"
)

type LocalSegmentRegistrationPlugin struct{}

var _ SegmentRegistrationPlugin = (*LocalSegmentRegistrationPlugin)(nil)

func (p *LocalSegmentRegistrationPlugin) ID() string {
	return "local"
}

func (p *LocalSegmentRegistrationPlugin) Validate(config map[string]any) error {
	// Local segment registration does not require any specific configuration.
	return nil
}

func (p *LocalSegmentRegistrationPlugin) New(
	ctx context.Context,
	pc PluginConstructor,
	segType seg.Type,
	policyType beacon.PolicyType,
	config map[string]any,
) (SegmentRegistrar, error) {
	return &LocalSegmentRegistrar{
		InternalErrors: pc.InternalErrors,
		Registered:     pc.Registered,
		Type:           segType,
		Store:          pc.LocalStore,
	}, nil
}

// LocalSegmentRegistrar can be used to write segments in the local SegmentStore.
type LocalSegmentRegistrar struct {
	// InternalErrors counts errors that happened before being able to store the
	// segment locally.
	InternalErrors metrics.Counter
	// Registered counts the amount of registered segments. A label is used to
	// indicate the status of the registration.
	Registered metrics.Counter
	// Type is the type of segment that is handled by this writer.
	Type seg.Type
	// Store is used to store the segments.
	Store beaconing.SegmentStore
}

var _ SegmentRegistrar = (*LocalSegmentRegistrar)(nil)

// RegisterSegments registers the segments in the local SegmentStore.
func (r *LocalSegmentRegistrar) RegisterSegments(
	ctx context.Context,
	beacons []beacon.Beacon,
	peers []uint16,
) (RegistrationStats, error) {
	// beacons keyed with their logging ID.
	logBeacons := make(map[string]beacon.Beacon)
	var toRegister []*seg.Meta
	for _, b := range beacons {
		toRegister = append(toRegister, &seg.Meta{Type: r.Type, Segment: b.Segment})
		logBeacons[b.Segment.GetLoggingID()] = b
	}
	if len(toRegister) == 0 {
		// Nothing to register.
		return RegistrationStats{}, nil
	}
	status := make(map[string]error, len(toRegister))
	stats, err := r.Store.StoreSegs(ctx, toRegister)
	// If an error occurred while storing, no segments were registered, since StoreSegs
	// does a batch insert. As a result, we report every segment failing with the returned error.
	if err != nil {
		metrics.CounterInc(r.InternalErrors)
		for _, b := range toRegister {
			status[string(b.Segment.FullID())] = err
		}
		return RegistrationStats{
			WriteStats: beaconing.WriteStats{
				Count:    0,
				StartIAs: make(map[addr.IA]struct{}),
			},
			Status: status,
		}, nil
	}
	r.updateMetricsFromStat(stats, logBeacons)
	sum := summarizeStats(stats, logBeacons)
	return RegistrationStats{
		WriteStats: beaconing.WriteStats{
			Count:    sum.count,
			StartIAs: sum.srcs,
		},
		Status: make(map[string]error),
	}, nil
}

// updateMetricsFromStat is used to update the metrics for local DB inserts.
func (r *LocalSegmentRegistrar) updateMetricsFromStat(
	s seghandler.SegStats,
	b map[string]beacon.Beacon,
) {
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
