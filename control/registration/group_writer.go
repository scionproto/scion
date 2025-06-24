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
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// GroupWriter is a beaconing.Writer that writes beacons across multiple segment registrars
// registered in Plugins. It is parameterized by a PolicyType, which determines the registrars
// that will be used.
type GroupWriter struct {
	PolicyType beacon.PolicyType
	Plugins    SegmentRegistrars
}

var _ beaconing.Writer = (*GroupWriter)(nil)

// Write writes beacons to multiple segment registrars based on the PolicyType.
//
// For every group of beacons, the correct registrar is selected based on the PolicyType
// and the group's name (which should correspond to the registration policy name).
func (w *GroupWriter) Write(
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
