// Copyright 2019 Anapaya Systems
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
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

// Verification types.
const (
	Chain     = "chain"
	Signature = "signature"
)

// LookupLabels defines the trust material lookup labels.
type LookupLabels struct {
	Client    string
	Trigger   string
	ReqType   string
	LocalOnly bool
	Result    string
}

// Labels returns the list of labels.
func (l LookupLabels) Labels() []string {
	return []string{"client", "trigger", "req_type", "local_only", prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l LookupLabels) Values() []string {
	localOnly := strconv.FormatBool(l.LocalOnly)
	return []string{l.Client, l.Trigger, l.ReqType, localOnly, l.Result}
}

// WithResult returns the lookup labels with the modified result.
func (l LookupLabels) WithResult(result string) LookupLabels {
	l.Result = result
	return l
}

// OutgoingLabels defines the outgoing request labels.
type OutgoingLabels struct {
	Client    string
	Server    string
	Trigger   string
	ReqType   string
	CacheOnly bool
	Result    string
}

// Labels returns the list of labels.
func (l OutgoingLabels) Labels() []string {
	return []string{"client", "server", "trigger", "req_type", "cache_only", prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l OutgoingLabels) Values() []string {
	cacheOnly := strconv.FormatBool(l.CacheOnly)
	return []string{l.Client, l.Server, l.Trigger, l.ReqType, cacheOnly, l.Result}
}

// WithResult returns the outgoing labels with the modified result.
func (l OutgoingLabels) WithResult(result string) OutgoingLabels {
	l.Result = result
	return l
}

// VerificationLabels defines the outgoing request labels.
type VerificationLabels struct {
	Type   string
	Result string
}

// Labels returns the list of labels.
func (l VerificationLabels) Labels() []string {
	return []string{"type", prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l VerificationLabels) Values() []string {
	return []string{l.Type, l.Result}
}

// WithResult returns the verification labels with the modified result.
func (l VerificationLabels) WithResult(result string) VerificationLabels {
	l.Result = result
	return l
}

type store struct {
	lookup       prometheus.CounterVec
	outgoing     prometheus.CounterVec
	verification prometheus.CounterVec
}

func newStore() store {
	return store{
		lookup: *prom.NewCounterVec(Namespace, "", "lookups_total",
			"Number of crypto lookups in the trust store", LookupLabels{}.Labels()),
		outgoing: *prom.NewCounterVec(Namespace, "", "outgoing_requests_total",
			"Number of requests initiated by the trust store", OutgoingLabels{}.Labels()),
		verification: *prom.NewCounterVec(Namespace, "", "signature_verifications_total",
			"Number of signature verifications done by trust store", VerificationLabels{}.Labels()),
	}
}

func (s *store) Lookup(l LookupLabels) prometheus.Counter {
	return s.lookup.WithLabelValues(l.Values()...)
}

func (s *store) Outgoing(l OutgoingLabels) prometheus.Counter {
	return s.outgoing.WithLabelValues(l.Values()...)
}

func (s *store) Verification(l VerificationLabels) prometheus.Counter {
	return s.verification.WithLabelValues(l.Values()...)
}
