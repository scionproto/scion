// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

const (
	// Namespace is the metrics namespace for the snet client API.
	Namespace = "lib_snet"

	subDials           = "dials"
	subListens         = "listens"
	subCloses          = "closes"
	subRead            = "read"
	subWrite           = "write"
	subSCMPError       = "scmp_error"
	subDispatcherError = "dispatcher_error"
	subParseError      = "parse_error"
)

var (
	// M exposes all the initialized metrics for this package.
	M = newMetrics()
)

type metrics struct {
	dials            prometheus.Counter
	listens          prometheus.Counter
	closes           prometheus.Counter
	readBytes        prometheus.Counter
	readPackets      prometheus.Counter
	writeBytes       prometheus.Counter
	writePackets     prometheus.Counter
	parseErrors      prometheus.Counter
	scmpErrors       prometheus.Counter
	dispatcherErrors prometheus.Counter
}

func newMetrics() metrics {
	return metrics{
		dials: prom.NewCounter(Namespace, subDials, "total",
			"Total number of Dial calls."),
		listens: prom.NewCounter(Namespace, subListens, "total",
			"Total number of Listen calls."),
		closes: prom.NewCounter(Namespace, subCloses, "total",
			"Total number of Close calls."),
		readBytes: prom.NewCounter(Namespace, subRead, "total_bytes",
			"Total number of bytes read"),
		readPackets: prom.NewCounter(Namespace, subRead, "total_pkts",
			"Total number of packetes read"),
		writeBytes: prom.NewCounter(Namespace, subWrite, "total_bytes",
			"Total number of bytes written"),
		writePackets: prom.NewCounter(Namespace, subWrite, "total_pkts",
			"Total number of packets written"),
		scmpErrors: prom.NewCounter(Namespace, subSCMPError, "total",
			"Total number of SCMP errors"),
		dispatcherErrors: prom.NewCounter(Namespace, subDispatcherError, "total",
			"Total number of dispatcher errors"),
		parseErrors: prom.NewCounter(Namespace, subParseError, "total",
			"Total number of parse errors"),
	}
}

// Dials returns the dials counter.
func (m metrics) Dials() prometheus.Counter {
	return m.dials
}

// Listens returns the listens counter.
func (m metrics) Listens() prometheus.Counter {
	return m.listens
}

// Closes returns the closes counter.
func (m metrics) Closes() prometheus.Counter {
	return m.closes
}

// ReadBytes returns the bytes read counter.
func (m metrics) ReadBytes() prometheus.Counter {
	return m.readBytes
}

// ReadPackets returns the packets read counter.
func (m metrics) ReadPackets() prometheus.Counter {
	return m.readPackets
}

// WriteBytes returns the bytes written counter.
func (m metrics) WriteBytes() prometheus.Counter {
	return m.writeBytes
}

// WritePackets returns the packets written counter.
func (m metrics) WritePackets() prometheus.Counter {
	return m.writePackets
}

// DispatcherErrors returns the dispather errors counter.
func (m metrics) DispatcherErrors() prometheus.Counter {
	return m.dispatcherErrors
}

// SCMPErrors returns the SCMP errors counter.
func (m metrics) SCMPErrors() prometheus.Counter {
	return m.scmpErrors
}

// ParseErrors returns the parse errors counter.
func (m metrics) ParseErrors() prometheus.Counter {
	return m.parseErrors
}
