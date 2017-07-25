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
	PktBytesRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "pkt_bytes_recv_total",
			Help:      "Number of packet bytes received.",
		},
		[]string{"intf"},
	)
	PktBytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "pkt_bytes_sent_total",
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
		[]string{"IA"},
	)
	FramesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "frames_sent_total",
			Help:      "Number of frames sent.",
		},
		[]string{"IA"},
	)
	FrameBytesRecv = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "frame_bytes_recv_total",
			Help:      "Number of frame bytes received.",
		},
		[]string{"IA"},
	)
	FrameBytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "frame_bytes_sent_total",
			Help:      "Number of frame bytes sent.",
		},
		[]string{"IA"},
	)
	FrameDiscardEvents = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "frame_discard_events_total",
			Help:      "Number of frame-discard events.",
		})
	FramesDiscarded = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "frames_discarded_total",
			Help:      "Number of frames discarded",
		})
	FramesTooOld = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "frames_too_old_total",
			Help:      "Number of frames that are too old",
		})
	FramesDuplicated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "sig",
			Name:      "frames_duplicated_total",
			Help:      "Number of duplicate frames",
		})
)

// Ensure all metrics are registered.
func init() {
	prometheus.MustRegister(PktsRecv)
	prometheus.MustRegister(PktsSent)
	prometheus.MustRegister(PktBytesRecv)
	prometheus.MustRegister(PktBytesSent)
	prometheus.MustRegister(FramesRecv)
	prometheus.MustRegister(FramesSent)
	prometheus.MustRegister(FrameBytesRecv)
	prometheus.MustRegister(FrameBytesSent)
	prometheus.MustRegister(FrameDiscardEvents)
	prometheus.MustRegister(FramesDiscarded)
	prometheus.MustRegister(FramesTooOld)
	prometheus.MustRegister(FramesDuplicated)
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
