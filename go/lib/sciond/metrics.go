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

package sciond

import (
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Metrics can be used to inject metrics counters into the sciond API. Each
// counter may be set or unset.
type Metrics struct {
	Connects                   metrics.Counter
	PathsRequests              metrics.Counter
	ASRequests                 metrics.Counter
	InterfacesRequests         metrics.Counter
	ServicesRequests           metrics.Counter
	InterfaceDownNotifications metrics.Counter
}

func (m Metrics) incConnects(err error)  { incMetric(m.Connects, err) }
func (m Metrics) incPaths(err error)     { incMetric(m.PathsRequests, err) }
func (m Metrics) incAS(err error)        { incMetric(m.ASRequests, err) }
func (m Metrics) incInterface(err error) { incMetric(m.InterfacesRequests, err) }
func (m Metrics) incServcies(err error)  { incMetric(m.ServicesRequests, err) }
func (m Metrics) incIfDown(err error)    { incMetric(m.InterfaceDownNotifications, err) }

func incMetric(c metrics.Counter, err error) {
	if c == nil {
		return
	}
	c.With(prom.LabelResult, errorToPrometheusLabel(err)).Add(1)
}

func errorToPrometheusLabel(err error) string {
	switch {
	case err == nil:
		return prom.Success
	case serrors.IsTimeout(err):
		return prom.ErrTimeout
	default:
		return prom.ErrNotClassified
	}
}
