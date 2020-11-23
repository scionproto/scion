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
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/pkg/gateway/routing"
)

// RoutingPolicyProvider provides the current active routing policy.
type RoutingPolicyProvider interface {
	RoutingPolicy() *routing.Policy
}

type PrefixesFilterMetrics struct {
	PrefixesAccepted metrics.Gauge
	PrefixesRejected metrics.Gauge
}

// PrefixesFilter is a prefix consumer that only forwards calls that are
// accepted by the current routing policy.
type PrefixesFilter struct {
	// LocalIA is that IA this filter is running in. It is used as from value in
	// the routing policy check.
	LocalIA addr.IA
	// Consumer is the component that consumes prefixes that are not filtered
	// out.
	Consumer PrefixConsumer
	// PolicyProvider is the provider of routing policies, must not be nil.
	PolicyProvider RoutingPolicyProvider
	// Metrics can be used to report information about accepted and rejected IP prefixes. If not
	// initialized, no metrics will be reported.
	Metrics PrefixesFilterMetrics
}

// Prefixes consumes the prefixes, if they are accepted by the policy they are
// forwarded to the registered consumer.
func (f PrefixesFilter) Prefixes(remote addr.IA, gateway Gateway, prefixes []*net.IPNet) {
	rp := f.PolicyProvider.RoutingPolicy()
	if rp == nil {
		return
	}
	var allowedPrefixes []*net.IPNet
	rejectedCount := 0
	for _, prefix := range prefixes {
		rule := rp.Match(remote, f.LocalIA, prefix)
		if rule.Action == routing.Accept {
			allowedPrefixes = append(allowedPrefixes, prefix)
		} else {
			rejectedCount++
		}
	}
	metrics.GaugeSet(metrics.GaugeWith(f.Metrics.PrefixesAccepted,
		"remote_isd_as", remote.String()), float64(len(allowedPrefixes)))
	metrics.GaugeSet(metrics.GaugeWith(f.Metrics.PrefixesRejected,
		"remote_isd_as", remote.String()), float64(rejectedCount))
	f.Consumer.Prefixes(remote, gateway, allowedPrefixes)
}
