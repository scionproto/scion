// Copyright 2021 Anapaya Systems
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

// Package metrics defines default initializers for the metrics structs that are used
// in the snet package.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/snet"
)

type Option func(*option)

// WithRegistry specifies the registerer used to create the metrics.
func WithRegistry(registry prometheus.Registerer) Option {
	return func(o *option) {
		o.registry = registry
	}
}

type option struct {
	registry prometheus.Registerer
}

func apply(opts []Option) option {
	o := option{registry: prometheus.DefaultRegisterer}
	for _, option := range opts {
		option(&o)
	}
	return o
}

func NewSCIONNetworkMetrics(opts ...Option) snet.SCIONNetworkMetrics {
	o := apply(opts)
	auto := promauto.With(o.registry)

	return snet.SCIONNetworkMetrics{
		Dials: metrics.NewCounter(auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_dials_total",
			Help: "Total number of Dial calls."})),
		Listens: metrics.NewCounter(auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_listens_total",
			Help: "Total number of Listen calls."})),
	}
}

func NewSCIONPacketConnMetrics(opts ...Option) snet.SCIONPacketConnMetrics {
	o := apply(opts)
	auto := promauto.With(o.registry)
	return snet.SCIONPacketConnMetrics{
		Closes: metrics.NewCounter(auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_closes_total",
			Help: "Total number of Close calls."})),
		ReadBytes: metrics.NewCounter(auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_read_total_bytes",
			Help: "Total number of bytes read"})),
		ReadPackets: metrics.NewCounter(auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_read_total_pkts",
			Help: "Total number of packetes read"})),
		WriteBytes: metrics.NewCounter(auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_write_total_bytes",
			Help: "Total number of bytes written"})),
		WritePackets: metrics.NewCounter(auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_write_total_pkts",
			Help: "Total number of packets written"})),
		DispatcherErrors: metrics.NewCounter(auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_dispatcher_error_total",
			Help: "Total number of dispatcher errors"})),
		ParseErrors: metrics.NewCounter(auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_parse_error_total",
			Help: "Total number of parse errors"})),
		SCMPErrors: NewSCMPErrors(opts...),
	}
}

func NewSCMPErrors(opts ...Option) metrics.SimpleCounter {
	o := apply(opts)
	auto := promauto.With(o.registry)

	return metrics.NewCounter(auto.NewCounter(prometheus.CounterOpts{
		Name: "lib_snet_scmp_error_total",
		Help: "Total number of SCMP errors"}))
}
