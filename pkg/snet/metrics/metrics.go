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

	"github.com/scionproto/scion/pkg/metrics/v2"
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
		Dials: auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_dials_total",
			Help: "Total number of Dial calls."}),
		Listens: auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_listens_total",
			Help: "Total number of Listen calls."}),
	}
}

func NewSCIONPacketConnMetrics(opts ...Option) snet.SCIONPacketConnMetrics {
	o := apply(opts)
	auto := promauto.With(o.registry)
	return snet.SCIONPacketConnMetrics{
		Closes: auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_closes_total",
			Help: "Total number of Close calls."}),
		ReadBytes: auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_read_total_bytes",
			Help: "Total number of bytes read"}),
		ReadPackets: auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_read_total_pkts",
			Help: "Total number of packetes read"}),
		WriteBytes: auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_write_total_bytes",
			Help: "Total number of bytes written"}),
		WritePackets: auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_write_total_pkts",
			Help: "Total number of packets written"}),
		UnderlayConnectionErrors: auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_underlay_error_total",
			Help: "Total number of underlay connection errors"}),
		ParseErrors: auto.NewCounter(prometheus.CounterOpts{
			Name: "lib_snet_parse_error_total",
			Help: "Total number of parse errors"}),
		SCMPErrors: NewSCMPErrors(opts...),
	}
}

func NewSCMPErrors(opts ...Option) metrics.Counter {
	o := apply(opts)
	auto := promauto.With(o.registry)

	return auto.NewCounter(prometheus.CounterOpts{
		Name: "lib_snet_scmp_error_total",
		Help: "Total number of SCMP errors"})
}
