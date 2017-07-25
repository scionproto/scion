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

var promAddr = flag.String("prom", "127.0.0.1:1281", "Address to export prometheus metrics on")

// Declare prometheus metrics to export.
var (
	PktsRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "pkts_recv_total",
			Help:      "Number of packets received.",
		},
		[]string{"intf"},
	)
	PktsSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "pkts_sent_total",
			Help:      "Number of packets sent.",
		},
		[]string{"intf"},
	)
	PktsBytesRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "pkts_bytes_recv_total",
			Help:      "Number of packet bytes received.",
		},
		[]string{"intf"},
	)
	PktsBytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "pkts_bytes_sent_total",
			Help:      "Number of packets bytes sent.",
		},
		[]string{"intf"},
	)
	FramesRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "frames_recv_total",
			Help:      "Number of frames received.",
		},
		[]string{"intf"},
	)
	FramesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "frames_sent_total",
			Help:      "Number of frames sent.",
		},
		[]string{"intf"},
	)
	FramesBytesRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "frames_bytes_recv_total",
			Help:      "Number of frame bytes received.",
		},
		[]string{"intf"},
	)
	FramesBytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "frames_bytes_sent_total",
			Help:      "Number of frame bytes sent.",
		},
		[]string{"intf"},
	)
)

// Ensure all metrics are registered.
func init() {
	prometheus.MustRegister(PktsRecv)
	prometheus.MustRegister(PktsSent)
	prometheus.MustRegister(PktsBytesRecv)
	prometheus.MustRegister(PktsBytesSent)
	prometheus.MustRegister(FramesRecv)
	prometheus.MustRegister(FramesSent)
	prometheus.MustRegister(FramesBytesRecv)
	prometheus.MustRegister(FramesBytesSent)
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
