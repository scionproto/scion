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
)

var promAddr = flag.String("prom", "127.0.0.1:1280", "Address to export prometheus metrics on")

// Declare prometheus metrics to export.
var (
	PktsRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "pkts_recv_total",
			Help:      "Number of packets received.",
		},
		[]string{"id"},
	)
	PktsSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "pkts_sent_total",
			Help:      "Number of packets sent.",
		},
		[]string{"id"},
	)
	BytesRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "bytes_recv_total",
			Help:      "Number of bytes received.",
		},
		[]string{"id"},
	)
	BytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "bytes_sent_total",
			Help:      "Number of bytes sent.",
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
		return common.NewError("Unable to bind prometheus metrics port", "err", err)
	}
	log.Info("Exporting prometheus metrics", "addr", *promAddr)
	go http.Serve(ln, nil)
	return nil
}
