// Copyright 2017 ETH Zurich
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
	"flag"
	"io"
	"net"
	"net/http"

	log "github.com/inconshreveable/log15"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/prom"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
)

var promAddr = flag.String("prom", "127.0.0.1:1281", "Address to export prometheus metrics on")

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
)

// Ensure all metrics are registered.
func Init(elem string) {
	namespace := "sig"
	constLabels := prometheus.Labels{"elem": elem}
	intfLabels := []string{"intf"}
	iaLabels := []string{"IA"}

	// Some closures to reduce boiler-plate.
	newC := func(name, help string) prometheus.Counter {
		v := prom.NewCounter(namespace, "", name, help, constLabels)
		prometheus.MustRegister(v)
		return v
	}
	newCVec := func(name, help string, lNames []string) *prometheus.CounterVec {
		v := prom.NewCounterVec(namespace, "", name, help, constLabels, lNames)
		prometheus.MustRegister(v)
		return v
	}
	// FIXME(kormat): these metrics should probably have more informative labels
	PktsRecv = newCVec("pkts_recv_total", "Number of packets received.", intfLabels)
	PktsSent = newCVec("pkts_sent_total", "Number of packets sent.", intfLabels)
	PktBytesRecv = newCVec("pkt_bytes_recv_total", "Number of packet bytes received.", intfLabels)
	PktBytesSent = newCVec("pkt_bytes_sent_total", "Number of packet bytes sent.", intfLabels)
	FramesRecv = newCVec("frames_recv_total", "Number of frames received.", iaLabels)
	FramesSent = newCVec("frames_sent_total", "Number of frames sent.", iaLabels)
	FrameBytesRecv = newCVec("frame_bytes_recv_total", "Number of frame bytes received.", iaLabels)
	FrameBytesSent = newCVec("frame_bytes_sent_total", "Number of frame bytes sent.", iaLabels)
	FrameDiscardEvents = newC("frame_discard_events_total", "Number of frame-discard events.")
	FramesDiscarded = newC("frames_discarded_total", "Number of frames discarded.")
	FramesTooOld = newC("frames_too_old_total", "Number of frames that are too old.")
	FramesDuplicated = newC("frames_duplicated_total", "Number of duplicate frames.")

	// Initialize ringbuf metrics.
	ringbuf.InitMetrics("sig", constLabels, []string{"ringId", "sessId"})
}

var servers map[string]io.Closer

func init() {
	servers = make(map[string]io.Closer)
	http.Handle("/metrics", promhttp.Handler())
}

// Export handles exposing prometheus metrics.
func Start() error {
	ln, err := net.Listen("tcp", *promAddr)
	if err != nil {
		return common.NewCError("Unable to bind prometheus metrics port", "err", err)
	}
	log.Info("Exporting prometheus metrics", "addr", *promAddr)
	go http.Serve(ln, nil)
	return nil
}
