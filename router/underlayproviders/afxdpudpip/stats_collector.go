// Copyright 2026 SCION Association
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

//go:build linux && (amd64 || arm64)

package afxdpudpip

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/underlay/afxdp"
	"github.com/scionproto/scion/private/underlay/ebpf"
)

// statsCollector exposes kernel-side drop counters for the afxdpudpip underlay:
//
//   - Per-NIC eBPF XDP_DROP counts, broken out by reason. Sourced from the
//     drop_counters BPF_MAP_TYPE_PERCPU_ARRAY in sockfilter.c.
//   - Per-(NIC, queue) AF_XDP socket stats from getsockopt(XDP_STATISTICS).
//
// Values are read at scrape time via Collect(). No polling goroutine.
type statsCollector struct {
	u *underlay

	xdpDropDesc   *prometheus.Desc
	afxdpStatDesc *prometheus.Desc
}

func newStatsCollector(u *underlay) *statsCollector {
	return &statsCollector{
		u: u,
		xdpDropDesc: prometheus.NewDesc(
			"router_xdp_drops_total",
			"Total packets dropped by the afxdpudpip XDP program, by reason.",
			[]string{"nic", "reason"},
			nil,
		),
		afxdpStatDesc: prometheus.NewDesc(
			"router_afxdp_socket_drops_total",
			"AF_XDP per-socket drop counters from getsockopt(XDP_STATISTICS).",
			[]string{"nic", "queue", "stat"},
			nil,
		),
	}
}

func (c *statsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.xdpDropDesc
	ch <- c.afxdpStatDesc
}

func (c *statsCollector) Collect(ch chan<- prometheus.Metric) {
	// All eBPF reads happen under u.mu so they cannot race with Stop, which
	// clears the maps before tearing down the underlying objects. Stop is
	// infrequent (shutdown only) and the data path does not take u.mu, so
	// the held duration here does not affect forwarding.
	type dropSample struct {
		nic    string
		totals [len(ebpf.DropReasonNames)]uint64
	}
	type sockSample struct {
		nic, queue string
		stats      afxdp.SocketStats
	}

	c.u.mu.Lock()
	drops := make([]dropSample, 0, len(c.u.allInterfaces))
	for _, iface := range c.u.allInterfaces {
		totals, err := iface.ReadDropCounters()
		if err != nil {
			log.Debug("reading xdp drop counters", "nic", iface.Name(), "err", err)
			continue
		}
		drops = append(drops, dropSample{nic: iface.Name(), totals: totals})
	}
	socks := make([]sockSample, 0, len(c.u.allConnections))
	for _, conn := range c.u.allConnections {
		stats, err := conn.socket.Stats()
		if err != nil {
			log.Debug("reading AF_XDP socket stats",
				"nic", conn.name, "queue", conn.queueID, "err", err)
			continue
		}
		socks = append(socks, sockSample{
			nic:   conn.name,
			queue: strconv.FormatUint(uint64(conn.queueID), 10),
			stats: stats,
		})
	}
	c.u.mu.Unlock()

	for _, d := range drops {
		for reason, v := range d.totals {
			ch <- prometheus.MustNewConstMetric(
				c.xdpDropDesc, prometheus.CounterValue, float64(v),
				d.nic, ebpf.DropReasonNames[reason],
			)
		}
	}
	for _, s := range socks {
		c.emitSocketStat(ch, s.nic, s.queue, "rx_dropped", s.stats.RxDropped)
		c.emitSocketStat(ch, s.nic, s.queue, "rx_invalid_descs", s.stats.RxInvalidDescs)
		c.emitSocketStat(ch, s.nic, s.queue, "tx_invalid_descs", s.stats.TxInvalidDescs)
		c.emitSocketStat(ch, s.nic, s.queue, "rx_ring_full", s.stats.RxRingFull)
		c.emitSocketStat(ch, s.nic, s.queue,
			"rx_fill_ring_empty_descs", s.stats.RxFillRingEmptyDescs)
		c.emitSocketStat(ch, s.nic, s.queue,
			"tx_ring_empty_descs", s.stats.TxRingEmptyDescs)
	}
}

func (c *statsCollector) emitSocketStat(
	ch chan<- prometheus.Metric, nic, queue, stat string, v uint64,
) {
	ch <- prometheus.MustNewConstMetric(
		c.afxdpStatDesc, prometheus.CounterValue, float64(v),
		nic, queue, stat,
	)
}
