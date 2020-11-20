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
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/pkg/gateway/control"
	"github.com/scionproto/scion/go/pkg/gateway/pathhealth"
	"github.com/scionproto/scion/go/pkg/gateway/pathhealth/policies"
)

// PathMonitor implements control.PathMonitor using a pathhealth path monitor.
type PathMonitor struct {
	*pathhealth.Monitor
	revStore              pathhealth.RevocationStore
	sessionPathsAvailable metrics.Gauge
}

func (pm *PathMonitor) Register(remote addr.IA, policies *policies.Policies,
	policyID int) control.PathMonitorRegistration {

	reg := pm.Monitor.Register(remote, &pathhealth.FilteringPathSelector{
		PathPolicy:      policies.PathPolicy,
		PathCount:       policies.PathCount,
		RevocationStore: pm.revStore,
	})
	return &registration{
		Registration: reg,
		sessionPathsAvailable: metrics.GaugeWith(
			pm.sessionPathsAvailable,
			"remote_isd_as", remote.String(),
			"policy_id", strconv.Itoa(policyID),
		),
	}
}

type registration struct {
	*pathhealth.Registration
	sessionPathsAvailable metrics.Gauge
}

func (r *registration) Get() pathhealth.Selection {
	selection := r.Registration.Get()
	if r.sessionPathsAvailable != nil {
		r.sessionPathsAvailable.With("status", "alive").Set(float64(selection.PathsAlive))
		r.sessionPathsAvailable.With("status", "timeout").Set(float64(selection.PathsDead))
		r.sessionPathsAvailable.With("status", "rejected").Set(float64(selection.PathsRejected))
	}
	return selection
}
