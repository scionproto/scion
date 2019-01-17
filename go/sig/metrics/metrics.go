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
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/sig/mgmt"
)

// Declare prometheus metrics to export.
var (
	PktsRecv           *prometheus.CounterVec
	PktsSent           *prometheus.CounterVec
	PktBytesRecv       *prometheus.CounterVec
	PktBytesSent       *prometheus.CounterVec
	FramesRecv         *prometheus.CounterVec
	FramesSent         *prometheus.CounterVec
	FrameBytesRecv     *prometheus.CounterVec
	FrameBytesSent     *prometheus.CounterVec
	FrameDiscardEvents prometheus.Counter
	FramesDiscarded    prometheus.Counter
	FramesTooOld       prometheus.Counter
	FramesDuplicated   prometheus.Counter

	EgressRxQueueFull *prometheus.CounterVec
)

// Version number of loaded config, atomic
var ConfigVersion uint64

// Ensure all metrics are registered.
func Init(elem string) {
	namespace := "sig"
	iaLabels := []string{"IA", "sessId"}
	prom.UseDefaultRegWithElem(elem)

	// Some closures to reduce boiler-plate.
	newC := func(name, help string) prometheus.Counter {
		return prom.NewCounter(namespace, "", name, help)
	}
	newCVec := func(name, help string, lNames []string) *prometheus.CounterVec {
		return prom.NewCounterVec(namespace, "", name, help, lNames)
	}
	// FIXME(kormat): these metrics should probably have more informative labels
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

	EgressRxQueueFull = newCVec("egress_recv_queue_full_total",
		"Egress packets dropped due to full queues.", []string{"IA"})

	// Initialize ringbuf metrics.
	ringbuf.InitMetrics("sig", []string{"ringId", "sessId"})
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
