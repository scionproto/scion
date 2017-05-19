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
	"io"
	"net"
	"net/http"

	log "github.com/inconshreveable/log15"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/netsec-ethz/scion/go/lib/common"
)

// Declare prometheus metrics to export.
var (
	PktsRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "border",
			Name:      "pkts_recv_total",
			Help:      "Number of packets received.",
		},
		[]string{"id"},
	)
	PktsSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "border",
			Name:      "pkts_sent_total",
			Help:      "Number of packets sent.",
		},
		[]string{"id"},
	)
	BytesRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "border",
			Name:      "bytes_recv_total",
			Help:      "Number of bytes received.",
		},
		[]string{"id"},
	)
	BytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "border",
			Name:      "bytes_sent_total",
			Help:      "Number of bytes sent.",
		},
		[]string{"id"},
	)
	PktBufNew = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "border",
		Name:      "pbuf_created_total",
		Help:      "Number of packet buffers created.",
	})
	PktBufReuse = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "border",
		Name:      "pbuf_reused_total",
		Help:      "Number of packet buffers reused.",
	})
	PktBufDiscard = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "border",
		Name:      "pbuf_discarded_total",
		Help:      "Number of packet buffers discarded.",
	})
	PktProcessTime = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "border",
		Name:      "pkt_process_seconds",
		Help:      "Packet processing time.",
	})
	IFState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "border",
			Name:      "interface_active",
			Help:      "Interface is active.",
		},
		[]string{"id"},
	)
	InputLoops = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "border",
			Name:      "input_loops",
			Help:      "Number of input loop runs.",
		},
		[]string{"id"},
	)
	InputProcessTime = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "border",
			Name:      "input_process_seconds",
			Help:      "Input processing time.",
		},
		[]string{"id"},
	)
	OutputProcessTime = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "border",
			Name:      "output_process_seconds",
			Help:      "Output processing time.",
		},
		[]string{"id"},
	)
)

// Ensure all metrics are registered.
func init() {
	prometheus.MustRegister(PktsRecv)
	prometheus.MustRegister(PktsSent)
	prometheus.MustRegister(BytesRecv)
	prometheus.MustRegister(BytesSent)
	prometheus.MustRegister(PktBufNew)
	prometheus.MustRegister(PktBufReuse)
	prometheus.MustRegister(PktBufDiscard)
	prometheus.MustRegister(PktProcessTime)
	prometheus.MustRegister(IFState)
	prometheus.MustRegister(InputLoops)
	prometheus.MustRegister(InputProcessTime)
	prometheus.MustRegister(OutputProcessTime)
}

var servers map[string]io.Closer

func init() {
	servers = make(map[string]io.Closer)
	http.Handle("/metrics", promhttp.Handler())
}

// Export accepts a slice of addresses in the form of "ip:port", and exports
// promethetus metrics on each address over http (if not done so already). It also
// stops exporting metrics on addresses that are not used anymore.
func Export(addresses []string) {
	newServers := make(map[string]io.Closer)
	for _, addr := range addresses {
		if _, ok := servers[addr]; ok {
			newServers[addr] = servers[addr]
			continue // Exporter already running on this address
		}
		// Run new exporter on addr.
		log.Info("Exporting metrics", "addr", addr)
		var closer io.Closer
		var err *common.Error
		if closer, err = listenAndServeWithClose(addr); err != nil {
			log.Error(err.String())
			continue
		}
		newServers[addr] = closer
	}
	// Stop exporting metrics on non-exported addresses.
	for addr, closer := range servers {
		if !contains(addresses, addr) {
			log.Info("Stop exporting metrics", "addr", addr)
			closer.Close()
		}
	}
	servers = newServers
}

func contains(addrs []string, addr string) bool {
	for _, entry := range addrs {
		if entry == addr {
			return true
		}
	}
	return false
}

func listenAndServeWithClose(addr string) (io.Closer, *common.Error) {
	var listener net.Listener
	var err error

	srv := &http.Server{Addr: addr}
	listener, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, common.NewError("Error setting up http server",
			"addr", addr, "err", err.Error())
	}
	go func() {
		err := srv.Serve(listener)
		if err != nil {
			log.Error("HTTP Server Error - ", "err", err)
		}
	}()

	return listener, nil
}
