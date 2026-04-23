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

package metrics

import (
	"net"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/snet"
)

// Trust material
const (
	Chain = "chain"
	TRC   = "trc"
)

// Request types
const (
	TRCReq    = "trc_request"
	ChainReq  = "chain_request"
	NotifyTRC = "trc_notify"
	LatestTRC = "latest_trc_number"
)

// Triggers
const (
	SigVerification = "signature_verification"
	ASInspector     = "trc_inspection"
	App             = "application"
)

// Result types
const (
	Success    = prom.Success
	OkExists   = "ok_exists"
	OkInserted = "ok_inserted"
	OkIgnored  = "ok_ignored"

	ErrMismatch   = "err_content_mismatch"
	ErrDB         = prom.ErrDB
	ErrInactive   = "err_inactive"
	ErrInternal   = prom.ErrInternal
	ErrKey        = "err_key"
	ErrNotAllowed = "err_not_allowed"
	ErrNotFound   = "err_not_found"
	ErrParse      = prom.ErrParse
	ErrTransmit   = "err_transmit"
	ErrValidate   = prom.ErrValidate
	ErrVerify     = prom.ErrVerify
)

// Metrics exposes trust-related metrics as functions that return counters.
type Metrics struct {
	ProviderRequests   func(reqType, result string) metrics.Counter
	RPCFetches         func(reqType, peer, result string) metrics.Counter
	SignerSignatures   func(result string) metrics.Counter
	SignerGenerated    func(result string) metrics.Counter
	VerifierSignatures func(result string) metrics.Counter
	CacheHits          func(typ, result string) metrics.Counter
}

func New(opts ...metrics.Option) Metrics {
	auto := metrics.ApplyOptions(opts...).Auto()

	providerRequests := auto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trustengine_lookups_total",
			Help: "Number of trust material lookups handled by the trust engine",
		},
		[]string{"type", "trigger", prom.LabelResult},
	)
	rpcFetches := auto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trustengine_sent_requests_total",
			Help: "Number of trust material requests sent by the trust store",
		},
		[]string{"type", "trigger", "peer", prom.LabelResult},
	)
	signerSignatures := auto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trustengine_created_signatures_total",
			Help: "Number of signatures created with a signer backed by the trust engine",
		},
		[]string{prom.LabelResult},
	)
	signerGenerated := auto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trustengine_generated_signers_total",
			Help: "Number of generated signers backed by the trust engine",
		},
		[]string{prom.LabelResult},
	)
	verifierSignatures := auto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trustengine_verified_signatures_total",
			Help: "Number of signatures verifications backed by the trust store",
		},
		[]string{prom.LabelResult},
	)
	cacheHits := auto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trustengine_cache_lookups_total",
			Help: "Total number of cache hits in the trust engine.",
		},
		[]string{"type", prom.LabelResult},
	)

	return Metrics{
		ProviderRequests: func(reqType, result string) metrics.Counter {
			// XXX(lukedirtwalker): in the old code the trigger was always
			// "application", so we hardcode it here.
			return providerRequests.WithLabelValues(reqType, App, result)
		},
		RPCFetches: func(reqType, peer, result string) metrics.Counter {
			// XXX(lukedirtwalker): in the old code the trigger was always
			// "application", so we hardcode it here.
			return rpcFetches.WithLabelValues(reqType, App, peer, result)
		},
		SignerSignatures: func(result string) metrics.Counter {
			return signerSignatures.WithLabelValues(result)
		},
		SignerGenerated: func(result string) metrics.Counter {
			return signerGenerated.WithLabelValues(result)
		},
		VerifierSignatures: func(result string) metrics.Counter {
			return verifierSignatures.WithLabelValues(result)
		},
		CacheHits: func(typ, result string) metrics.Counter {
			return cacheHits.WithLabelValues(typ, result)
		},
	}
}

// PeerToLabel converts the peer address to a peer metric label.
func PeerToLabel(peer net.Addr, local addr.IA) string {
	var ia addr.IA
	switch v := peer.(type) {
	case *snet.SVCAddr:
		ia = v.IA
	case *snet.UDPAddr:
		ia = v.IA
	case *net.TCPAddr:
		return "as_local"
	default:
		return "unknown"
	}

	switch {
	case ia.Equal(local):
		return "as_local"
	case ia.ISD() == local.ISD():
		return "isd_local"
	default:
		return "isd_remote"
	}
}
