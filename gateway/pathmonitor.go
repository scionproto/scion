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

package gateway

import (
	"context"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/pathhealth"
	"github.com/scionproto/scion/gateway/pathhealth/policies"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics"
)

// PathMonitor implements control.PathMonitor using a pathhealth path monitor.
type PathMonitor struct {
	*pathhealth.Monitor
	revStore              pathhealth.RevocationStore
	sessionPathsAvailable metrics.Gauge
}

func (pm *PathMonitor) Register(
	ctx context.Context,
	remote addr.IA,
	policies *policies.Policies,
	policyID string,
) control.PathMonitorRegistration {
	reg := pm.Monitor.Register(remote, &pathhealth.FilteringPathSelector{
		PathPolicy:      policies.PathPolicy,
		PathCount:       policies.PathCount,
		RevocationStore: pm.revStore,
	})
	return &registration{
		Registration: reg,
		alivePaths: metrics.GaugeWith(
			pm.sessionPathsAvailable,
			"remote_isd_as", remote.String(),
			"policy_id", policyID,
			"status", "alive",
		),
		timedoutPaths: metrics.GaugeWith(
			pm.sessionPathsAvailable,
			"remote_isd_as", remote.String(),
			"policy_id", policyID,
			"status", "timeout",
		),
		rejectedPaths: metrics.GaugeWith(
			pm.sessionPathsAvailable,
			"remote_isd_as", remote.String(),
			"policy_id", policyID,
			"status", "rejected",
		),
	}
}

type registration struct {
	*pathhealth.Registration
	alivePaths    metrics.Gauge
	timedoutPaths metrics.Gauge
	rejectedPaths metrics.Gauge
}

func (r *registration) Get() pathhealth.Selection {
	selection := r.Registration.Get()
	metrics.GaugeSet(r.alivePaths, float64(selection.PathsAlive))
	metrics.GaugeSet(r.timedoutPaths, float64(selection.PathsDead))
	metrics.GaugeSet(r.rejectedPaths, float64(selection.PathsRejected))
	return selection
}
