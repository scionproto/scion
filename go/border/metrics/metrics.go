// Copyright 2016 ETH Zurich
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

// Package metrics defines and exports router metrics to be scraped by
// prometheus.
package metrics

import (
	"flag"
	"net"
	"net/http"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay/conn"
	"github.com/netsec-ethz/scion/go/lib/prom"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
)

var promAddr = flag.String("prom", "127.0.0.1:1280", "Address to export prometheus metrics on")

// Declare prometheus metrics to export.
var (
	PktsRecv          *prometheus.CounterVec
	PktsSent          *prometheus.CounterVec
	PktsRecvSize      *prometheus.HistogramVec
	BytesRecv         *prometheus.CounterVec
	BytesSent         *prometheus.CounterVec
	PktProcessTime    prometheus.Counter
	IFState           *prometheus.GaugeVec
	InputLoops        *prometheus.CounterVec
	OutputLoops       *prometheus.CounterVec
	InputProcessTime  *prometheus.CounterVec
	OutputProcessTime *prometheus.CounterVec
)

// Ensure all metrics are registered.
func Init(elem string) {
	namespace := "border"
	constLabels := prometheus.Labels{"elem": elem}
	sockLabels := []string{"sock"}

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
	newGVec := func(name, help string, lNames []string) *prometheus.GaugeVec {
		v := prom.NewGaugeVec(namespace, "", name, help, constLabels, lNames)
		prometheus.MustRegister(v)
		return v
	}
	newHVec := func(name, help string, lNames []string, buckets []float64) *prometheus.HistogramVec {
		v := prom.NewHistogramVec(namespace, "", name, help, constLabels, lNames, buckets)
		prometheus.MustRegister(v)
		return v
	}

	// Initialize br metrics.
	PktsRecv = newCVec("pkts_recv_total", "Number of packets received.", sockLabels)
	PktsSent = newCVec("pkts_sent_total", "Number of packets sent.", sockLabels)
	PktsRecvSize = newHVec("pkts_recv_size", "Size of received packets", sockLabels,
		[]float64{64, 256, 512, 1024, 1280, 1500, 3000, 6000, 9000})
	BytesRecv = newCVec("bytes_recv_total", "Number of bytes received.", sockLabels)
	BytesSent = newCVec("bytes_sent_total", "Number of bytes sent.", sockLabels)
	PktProcessTime = newC("pkt_process_seconds", "Packet processing time.")
	IFState = newGVec("interface_active", "Interface is active.", sockLabels)
	InputLoops = newCVec("input_loops", "Number of input loop runs.", sockLabels)
	OutputLoops = newCVec("output_loops", "Number of output loop runs.", sockLabels)
	InputProcessTime = newCVec("input_process_seconds", "Input processing time.", sockLabels)
	OutputProcessTime = newCVec("output_process_seconds", "Output processing time.", sockLabels)

	// Initialize ringbuf metrics.
	ringbuf.InitMetrics("border", constLabels, []string{"ringId"})
	// Initialize overlay.conn metrics.
	conn.InitMetrics("border", constLabels, sockLabels)

	http.Handle("/metrics", promhttp.Handler())
}

// Start handles exposing prometheus metrics.
func Start() *common.Error {
	ln, err := net.Listen("tcp", *promAddr)
	if err != nil {
		return common.NewError("Unable to bind prometheus metrics port", "err", err)
	}
	log.Info("Exporting prometheus metrics", "addr", *promAddr)
	go http.Serve(ln, nil)
	return nil
}
