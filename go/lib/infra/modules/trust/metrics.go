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
package trust

import (
	"net"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	promSubsystem = "trust_store"

	promLabelIsd    = "isd"
	promLabelSrc    = "src"
	promLabelErr    = "err_type"
	promLabelCached = "cached"

	promSrcASLocal   = "as_local"
	promSrcISDLocal  = "isd_local"
	promSrcISDRemote = "isd_remote"
	promSrcUnknown   = "unknown"

	promCachedYes = "yes"
	promCachedNo  = "no"
)

var metrics *counters

type counters struct {
	localIA addr.IA

	trcGetTotal  *prometheus.CounterVec
	trcGetResult *prometheus.CounterVec

	chainGetTotal  *prometheus.CounterVec
	chainGetResult *prometheus.CounterVec
}

// InitMetrics initializes the metrics for the trust store.
func InitMetrics(elem, namespace string, localIA addr.IA) {
	metrics = &counters{
		localIA: localIA,
		// Cardinality: 3 (src) * #ISDs
		trcGetTotal: prom.NewCounterVec(namespace, promSubsystem, "trc_get_total",
			"Number of GetTRC calls total.", []string{promLabelSrc, promLabelIsd}),
		// Cardinality: 2 (cached) * x (error) * #ISDs
		trcGetResult: prom.NewCounterVec(namespace, promSubsystem, "trc_get_result",
			"Result of the GetTRC calls.",
			[]string{promLabelIsd, promLabelCached, promLabelErr}),
		// Cardinality: 3 (src)
		chainGetTotal: prom.NewCounterVec(namespace, promSubsystem, "chain_get_total",
			"Number of GetChain calls total.", []string{promLabelSrc}),
		// Cardinality: 2 (cached) * x (error)
		chainGetResult: prom.NewCounterVec(namespace, promSubsystem, "chain_get_result",
			"Result of the GetChain calls.", []string{promLabelCached, promLabelErr}),
	}
}

func (m *counters) incTRCGet(isd addr.ISD, client net.Addr, storedLocally bool, err error) {
	if m == nil {
		return
	}
	isdv := isd.String()
	// count all requests:
	totalLabels := prometheus.Labels{
		promLabelSrc: m.src(client),
		promLabelIsd: isdv,
	}
	m.trcGetTotal.With(totalLabels).Inc()
	errDesc := errorDesc(err)
	cached := promCachedYes
	if !storedLocally {
		cached = promCachedNo
	}
	resultLabels := prometheus.Labels{
		promLabelIsd:    isdv,
		promLabelCached: cached,
		promLabelErr:    errDesc,
	}
	m.trcGetResult.With(resultLabels).Inc()
}

func (m *counters) incChainGet(valid bool, client net.Addr, storedLocally bool, err error) {
	if m == nil {
		return
	}
	totalLabels := prometheus.Labels{
		promLabelSrc: m.src(client),
	}
	m.chainGetTotal.With(totalLabels).Inc()
	errDesc := errorDesc(err)
	cached := promCachedYes
	if !storedLocally {
		cached = promCachedNo
	}
	resultLabels := prometheus.Labels{
		promLabelErr:    errDesc,
		promLabelCached: cached,
	}
	m.chainGetResult.With(resultLabels).Inc()
}

func (m *counters) src(client net.Addr) string {
	if client == nil {
		return promSrcASLocal
	}
	saddr, ok := client.(*snet.Addr)
	if !ok {
		return promSrcUnknown
	}
	if m.localIA.Eq(saddr.IA) {
		return promSrcASLocal
	}
	if m.localIA.I == saddr.IA.I {
		return promSrcISDLocal
	}
	return promSrcISDRemote
}

func errorDesc(err error) string {
	if err == nil {
		return "none"
	}
	// TODO(lukedirtwalker): In the future we should categorize the errors better.
	switch {
	case common.IsTimeoutErr(err):
		return "err_timeout"
	default:
		return "err_any"
	}
}
