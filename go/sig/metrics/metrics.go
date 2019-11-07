// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package metrics publishes information about SIG operation
// NOTE(all): Work in progress, do not recommend reviewing this code yet
package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/sig/mgmt"
)

// Namespace is the metrics namespace for the SIG.
const Namespace = "sig"

// Declare prometheus metrics to export.
var (
	PktUnroutable         prometheus.Counter
	PktsRecv              *prometheus.CounterVec
	PktsSent              *prometheus.CounterVec
	PktBytesRecv          *prometheus.CounterVec
	PktBytesSent          *prometheus.CounterVec
	FramesRecv            *prometheus.CounterVec
	FramesSent            *prometheus.CounterVec
	FrameBytesRecv        *prometheus.CounterVec
	FrameBytesSent        *prometheus.CounterVec
	FrameDiscardEvents    prometheus.Counter
	FramesDiscarded       prometheus.Counter
	FramesTooOld          prometheus.Counter
	FramesDuplicated      prometheus.Counter
	SessionTimedOut       *prometheus.CounterVec
	SessionPathSwitched   *prometheus.CounterVec
	SessionOldPollReplies *prometheus.CounterVec
	SessionProbes         *prometheus.CounterVec
	SessionProbeReplies   *prometheus.CounterVec
	SessionProbeRTT       *prometheus.HistogramVec
	SessionPaths          *prometheus.GaugeVec
	SessionMTU            *prometheus.GaugeVec
	SessionHealth         *prometheus.GaugeVec
	SessionRemoteSwitched *prometheus.CounterVec

	EgressRxQueueFull *prometheus.CounterVec
)

// Version number of loaded config, atomic
var ConfigVersion uint64

func init() {
	iaLabels := []string{"IA", "sessId"}

	// Some closures to reduce boiler-plate.
	newC := func(name, help string) prometheus.Counter {
		return prom.NewCounter(Namespace, "", name, help)
	}
	newCVec := func(name, help string, lNames []string) *prometheus.CounterVec {
		return prom.NewCounterVec(Namespace, "", name, help, lNames)
	}
	newHVec := func(name, help string, lNames []string,
		buckets []float64) *prometheus.HistogramVec {

		return prom.NewHistogramVec(Namespace, "", name, help, lNames, buckets)
	}
	newGVec := func(name, help string, lNames []string) *prometheus.GaugeVec {
		return prom.NewGaugeVec(Namespace, "", name, help, lNames)
	}
	// FIXME(kormat): these metrics should probably have more informative labels
	PktUnroutable = newC("pkt_unroutable",
		"Number of egress packets that can't be routed to any remote AS.")
	PktsRecv = newCVec("pkts_recv_total", "Number of packets received.", iaLabels)
	PktsSent = newCVec("pkts_sent_total", "Number of packets sent.", iaLabels)
	PktBytesRecv = newCVec("pkt_bytes_recv_total", "Number of packet bytes received.", iaLabels)
	PktBytesSent = newCVec("pkt_bytes_sent_total", "Number of packet bytes sent.", iaLabels)
	FramesRecv = newCVec("frames_recv_total", "Number of frames received.", iaLabels)
	FramesSent = newCVec("frames_sent_total", "Number of frames sent.", iaLabels)
	FrameBytesRecv = newCVec("frame_bytes_recv_total", "Number of frame bytes received.", iaLabels)
	FrameBytesSent = newCVec("frame_bytes_sent_total", "Number of frame bytes sent.", iaLabels)
	FrameDiscardEvents = newC("frame_discard_events_total", "Number of frame-discard events.")
	FramesDiscarded = newC("frames_discarded_total", "Number of frames discarded.")
	FramesTooOld = newC("frames_too_old_total", "Number of frames that are too old.")
	FramesDuplicated = newC("frames_duplicated_total", "Number of duplicate frames.")
	SessionTimedOut = newCVec("session_timeout", "Number of pollreq timeouts", iaLabels)
	SessionPathSwitched = newCVec("session_switch_path", "Number of path switches",
		append(iaLabels, "reason"))
	SessionOldPollReplies = newCVec("session_old_poll_replies",
		"Number of poll replies received after next poll request was sent", iaLabels)
	SessionProbes = newCVec("session_probes", "Number of probes sent", iaLabels)
	SessionProbeReplies = newCVec("session_probe_replies",
		"Number of probe replies received", iaLabels)
	SessionProbeRTT = newHVec("session_probe_rtt", "Probe roundtrip time",
		iaLabels, prom.DefaultLatencyBuckets)
	SessionPaths = newGVec("session_paths", "Number of available paths", iaLabels)
	SessionMTU = newGVec("session_mtu", "MTU used by the session", iaLabels)
	SessionHealth = newGVec("session_health", "Session health (either 1 or 0)", iaLabels)
	SessionRemoteSwitched = newCVec("session_switch_remote",
		"Number of times the remote has changed.", iaLabels)

	EgressRxQueueFull = newCVec("egress_recv_queue_full_total",
		"Egress packets dropped due to full queues.", []string{"IA"})

	// Add handler for ConfigVersion
	http.HandleFunc("/configversion", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, atomic.LoadUint64(&ConfigVersion))
	})
}

// CtrPair is a pair of counters, one for packets and one for bytes.
type CtrPair struct {
	Pkts  prometheus.Counter
	Bytes prometheus.Counter
}

type CtrPairKey struct {
	RemoteIA addr.IAInt
	SessId   mgmt.SessionType
}
