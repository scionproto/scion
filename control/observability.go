// Copyright 2020 Anapaya Systems
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

package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	cstrust "github.com/scionproto/scion/control/trust"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/snet"
	snetmetrics "github.com/scionproto/scion/pkg/snet/metrics"
	"github.com/scionproto/scion/private/ca/renewal"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/discovery"
	"github.com/scionproto/scion/private/env"
	"github.com/scionproto/scion/private/service"
	"github.com/scionproto/scion/private/topology"
)

// InitTracer initializes the global tracer.
func InitTracer(tracing env.Tracing, id string) (io.Closer, error) {
	tracer, trCloser, err := tracing.NewTracer(id)
	if err != nil {
		return nil, err
	}
	opentracing.SetGlobalTracer(tracer)
	return trCloser, nil
}

// Metrics defines the metrics exposed by the control server.
//
// XXX(roosd): Currently, most counters are created in the packages. The will
// eventually be moved here.
type Metrics struct {
	BeaconDBQueriesTotal                   *prometheus.CounterVec
	BeaconingOriginatedTotal               *prometheus.CounterVec
	BeaconingPropagatedTotal               *prometheus.CounterVec
	BeaconingPropagatorInternalErrorsTotal *prometheus.CounterVec
	BeaconingReceivedTotal                 *prometheus.CounterVec
	BeaconingRegisteredTotal               *prometheus.CounterVec
	BeaconingRegistrarInternalErrorsTotal  *prometheus.CounterVec
	CAHealth                               *prometheus.GaugeVec
	DiscoveryRequestsTotal                 *prometheus.CounterVec
	PathDBQueriesTotal                     *prometheus.CounterVec
	RenewalServerRequestsTotal             *prometheus.CounterVec
	RenewalHandledRequestsTotal            *prometheus.CounterVec
	RenewalRegisteredHandlers              *prometheus.GaugeVec
	SegmentLookupRequestsTotal             *prometheus.CounterVec
	SegmentLookupSegmentsSentTotal         *prometheus.CounterVec
	SegmentRegistrationsTotal              *prometheus.CounterVec
	TrustDBQueriesTotal                    *prometheus.CounterVec
	TrustLatestTRCNotBefore                prometheus.Gauge
	TrustLatestTRCNotAfter                 prometheus.Gauge
	TrustLatestTRCSerial                   prometheus.Gauge
	TrustTRCFileWritesTotal                *prometheus.CounterVec
	SCIONNetworkMetrics                    snet.SCIONNetworkMetrics
	SCIONPacketConnMetrics                 snet.SCIONPacketConnMetrics
	SCMPErrors                             metrics.Counter
	TopoLoader                             topology.LoaderMetrics
}

func NewMetrics() *Metrics {
	scionPacketConnMetrics := snetmetrics.NewSCIONPacketConnMetrics()
	return &Metrics{
		BeaconDBQueriesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "beacondb_queries_total",
				Help: "Total queries to the database",
			},
			[]string{"driver", "operation", prom.LabelResult},
		),
		BeaconingOriginatedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "control_beaconing_originated_beacons_total",
				Help: "Total number of beacons originated.",
			},
			[]string{"egress_interface", prom.LabelResult},
		),
		BeaconingPropagatedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "control_beaconing_propagated_beacons_total",
				Help: "Total number of beacons propagated.",
			},
			[]string{"start_isd_as", "ingress_interface", "egress_interface", prom.LabelResult},
		),
		BeaconingPropagatorInternalErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "control_beaconing_propagator_internal_errors_total",
				Help: "Total number of internal errors in the beacon propagator.",
			},
			[]string{},
		),
		BeaconingReceivedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "control_beaconing_received_beacons_total",
				Help: "Total number of beacons received.",
			},
			[]string{"ingress_interface", prom.LabelNeighIA, prom.LabelResult},
		),
		BeaconingRegisteredTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "control_beaconing_registered_segments_total",
				Help: "Total number of segments registered.",
			},
			[]string{"start_isd_as", "ingress_interface", "seg_type", prom.LabelResult},
		),
		BeaconingRegistrarInternalErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "control_beaconing_registrar_internal_errors_total",
				Help: "Total number of internal errors in the beacon registrar.",
			},
			[]string{"seg_type"},
		),
		CAHealth: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "renewal_ca_health_status",
				Help: "Exposes the status of the CA (available, unavailable, starting, stopping)," +
					" if the host acts as CA and is delegating certificate renewal " +
					"to the CA service.",
			},
			[]string{"status"},
		),
		DiscoveryRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "discovery_requests_total",
				Help: "Total number of discovery requests served.",
			},
			discovery.Topology{}.RequestsLabels(),
		),
		PathDBQueriesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "pathdb_queries_total",
				Help: "Total queries to the database",
			},
			[]string{"driver", "operation", prom.LabelResult},
		),
		RenewalServerRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "renewal_received_requests_total",
				Help: "Total number of renewal requests served.",
			},
			[]string{prom.LabelResult},
		),
		RenewalHandledRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "renewal_handled_requests_total",
				Help: "Total number of renewal requests served by each handler type" +
					" (legacy, in-process, delegating).",
			},
			[]string{prom.LabelResult, "type"},
		),
		RenewalRegisteredHandlers: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "renewal_registered_handlers",
				Help: "Exposes which handler type (legacy, in-process, delegating) is registered.",
			},
			[]string{"type"},
		),
		SegmentLookupRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "control_segment_lookup_requests_total",
				Help: "Total number of path segments requests received.",
			},
			[]string{"dst_isd", "seg_type", prom.LabelResult},
		),
		SegmentLookupSegmentsSentTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "control_segment_lookup_segments_sent_total",
				Help: "Total number of path segments sent in the replies.",
			},
			[]string{"dst_isd", "seg_type"},
		),
		SegmentRegistrationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "control_segment_registry_segments_received_total",
				Help: "Total number of path segments received through registrations.",
			},
			[]string{"src", "seg_type", prom.LabelResult},
		),
		TrustDBQueriesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "trustengine_db_queries_total",
				Help: "Total queries to the database",
			},
			[]string{"driver", "operation", prom.LabelResult},
		),
		TrustLatestTRCNotBefore: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "trustengine_latest_trc_not_before_time_seconds",
				Help: "The not_before time of the latest TRC for the local ISD " +
					"in seconds since UNIX epoch.",
			},
		),
		TrustLatestTRCNotAfter: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "trustengine_latest_trc_not_after_time_seconds",
				Help: "The not_after time of the latest TRC for the local ISD " +
					"in seconds since UNIX epoch.",
			},
		),
		TrustLatestTRCSerial: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "trustengine_latest_trc_serial_number",
				Help: "The serial number of the latest TRC for the local ISD.",
			},
		),
		TrustTRCFileWritesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "trustengine_trc_file_writes_total",
				Help: "Total TRC filesystem file operations.",
			},
			[]string{prom.LabelResult},
		),
		SCIONNetworkMetrics:    snetmetrics.NewSCIONNetworkMetrics(),
		SCIONPacketConnMetrics: scionPacketConnMetrics,
		SCMPErrors:             scionPacketConnMetrics.SCMPErrors,
		TopoLoader:             loaderMetrics(),
	}
}

// RegisterHTTPEndpoints starts the HTTP endpoints that expose the metrics and
// additional information.
func RegisterHTTPEndpoints(
	elemId string,
	cfg config.Config,
	signer cstrust.RenewingSigner,
	ca renewal.ChainBuilder,
	topo *topology.Loader,
) error {
	statusPages := service.StatusPages{
		"info":      service.NewInfoStatusPage(),
		"config":    service.NewConfigStatusPage(cfg),
		"log/level": service.NewLogLevelStatusPage(),
		"signer":    signerStatusPage(signer),
	}
	if topo != nil {
		statusPages["topology"] = service.NewTopologyStatusPage(topo)
	}
	if ca != (renewal.ChainBuilder{}) {
		statusPages["ca"] = caStatusPage(ca)
	}
	if err := statusPages.Register(http.DefaultServeMux, elemId); err != nil {
		return serrors.WrapStr("registering status pages", err)
	}
	return nil
}

func signerStatusPage(signer cstrust.RenewingSigner) service.StatusPage {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s, err := signer.SignerGen.Generate(r.Context())
		if err != nil {
			http.Error(w, "Unable to get signer", http.StatusInternalServerError)
			return
		}

		type Subject struct {
			IA addr.IA `json:"isd_as"`
		}
		type TRCID struct {
			ISD    addr.ISD        `json:"isd"`
			Base   scrypto.Version `json:"base_number"`
			Serial scrypto.Version `json:"serial_number"`
		}
		type Validity struct {
			NotBefore time.Time `json:"not_before"`
			NotAfter  time.Time `json:"not_after"`
		}
		rep := struct {
			Subject       Subject   `json:"subject"`
			SubjectKeyID  string    `json:"subject_key_id"`
			Expiration    time.Time `json:"expiration"`
			TRCID         TRCID     `json:"trc_id"`
			ChainValidity Validity  `json:"chain_validity"`
			InGrace       bool      `json:"in_grace_period"`
		}{
			Subject:      Subject{IA: s.IA},
			SubjectKeyID: fmt.Sprintf("% X", s.SubjectKeyID),
			Expiration:   s.Expiration,
			TRCID: TRCID{
				ISD:    s.TRCID.ISD,
				Base:   s.TRCID.Base,
				Serial: s.TRCID.Serial,
			},
			ChainValidity: Validity{
				NotBefore: s.ChainValidity.NotBefore,
				NotAfter:  s.ChainValidity.NotAfter,
			},
			InGrace: s.InGrace,
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "    ")
		if err := enc.Encode(rep); err != nil {
			http.Error(w, "Unable to marshal response", http.StatusInternalServerError)
			return
		}
	}
	return service.StatusPage{
		Info:    "SCION signer info",
		Handler: handler,
	}
}

func caStatusPage(signer renewal.ChainBuilder) service.StatusPage {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s, err := signer.PolicyGen.Generate(r.Context())
		if err != nil {
			http.Error(w, "No active signer", http.StatusInternalServerError)
			return
		}

		ia, err := cppki.ExtractIA(s.Certificate.Subject)
		if err != nil {
			http.Error(w, "Unable to get extract ISD-AS", http.StatusInternalServerError)
			return
		}

		type Subject struct {
			IA addr.IA `json:"isd_as"`
		}
		type Validity struct {
			NotBefore time.Time `json:"not_before"`
			NotAfter  time.Time `json:"not_after"`
		}
		type Policy struct {
			ChainLifetime string `json:"chain_lifetime"`
		}
		rep := struct {
			Subject      Subject  `json:"subject"`
			SubjectKeyID string   `json:"subject_key_id"`
			Policy       Policy   `json:"policy"`
			CertValidity Validity `json:"cert_validity"`
		}{
			Subject:      Subject{IA: ia},
			SubjectKeyID: fmt.Sprintf("% X", s.Certificate.SubjectKeyId),
			Policy: Policy{
				ChainLifetime: s.Validity.String(),
			},
			CertValidity: Validity{
				NotBefore: s.Certificate.NotBefore,
				NotAfter:  s.Certificate.NotAfter,
			},
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "    ")
		if err := enc.Encode(rep); err != nil {
			http.Error(w, "Unable to marshal response", http.StatusInternalServerError)
			return
		}
	}
	return service.StatusPage{
		Info:    "CA status",
		Handler: handler,
	}
}

func loaderMetrics() topology.LoaderMetrics {
	updates := prom.NewCounterVec("", "",
		"topology_updates_total",
		"The total number of updates.",
		[]string{prom.LabelResult},
	)
	return topology.LoaderMetrics{
		ValidationErrors: metrics.NewPromCounter(updates).With(prom.LabelResult, "err_validate"),
		ReadErrors:       metrics.NewPromCounter(updates).With(prom.LabelResult, "err_read"),
		LastUpdate: metrics.NewPromGauge(
			prom.NewGaugeVec("", "",
				"topology_last_update_time",
				"Timestamp of the last successful update.",
				[]string{},
			),
		),
		Updates: metrics.NewPromCounter(updates).With(prom.LabelResult, prom.Success),
	}
}
