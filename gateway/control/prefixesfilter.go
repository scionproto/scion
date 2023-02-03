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

	"go4.org/netipx"

	"github.com/scionproto/scion/gateway/routing"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
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
func (f PrefixesFilter) Prefixes(
	remote addr.IA,
	gateway Gateway,
	prefixes []*net.IPNet,
) error {
	rp := f.PolicyProvider.RoutingPolicy()
	if rp == nil {
		return nil
	}
	var sb netipx.IPSetBuilder
	allowedCount := 0
	rejectedCount := 0
	for _, prefix := range prefixes {
		p, ok := netipx.FromStdIPNet(prefix)
		if !ok {
			return serrors.New("can not convert prefix", "prefix", prefix)
		}
		set, err := rp.Match(remote, f.LocalIA, p)
		if err != nil {
			return serrors.New("error while filtering prefix", "prefix", prefix, "err", err)
		}
		sb.AddSet(&set.IPSet)
		if len(set.Prefixes()) > 0 {
			allowedCount++
		} else {
			rejectedCount++
		}
	}
	metrics.GaugeSet(metrics.GaugeWith(f.Metrics.PrefixesAccepted,
		"remote_isd_as", remote.String()), float64(allowedCount))
	metrics.GaugeSet(metrics.GaugeWith(f.Metrics.PrefixesRejected,
		"remote_isd_as", remote.String()), float64(rejectedCount))

	set, err := sb.IPSet()
	if err != nil {
		return serrors.New("error while filtering prefixes", "prefixes", prefixes, "err", err)
	}
	var allowedPrefixes []*net.IPNet
	for _, prefix := range set.Prefixes() {
		allowedPrefixes = append(allowedPrefixes, netipx.PrefixIPNet(prefix))
	}
	return f.Consumer.Prefixes(remote, gateway, allowedPrefixes)
}
