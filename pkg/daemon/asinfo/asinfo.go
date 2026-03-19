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

package asinfo

import (
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/topology"
)

// LocalASInfo provides control plane information for the daemon engine.
type LocalASInfo interface {
	// IA returns the local ISD-AS number.
	IA() addr.IA
	// MTU returns the MTU of the local AS.
	MTU() uint16
	// Core returns whether the local AS is core.
	Core() bool
	// IfIDs InterfaceIDs returns all interface IDS from the local AS.
	IfIDs() []uint16
	// UnderlayNextHop returns the internal underlay address of the router
	// containing the interface ID.
	UnderlayNextHop(uint16) *net.UDPAddr
	// ControlServiceAddresses returns the addresses of the control services
	ControlServiceAddresses() []*net.UDPAddr
	// PortRange returns the first and last ports of the port range (both included),
	// in which endhost listen for SCION/UDP application using the UDP/IP underlay.
	PortRange() (uint16, uint16)
}

// LoadFromTopoFile loads a control plane info from a file.
// The returned LocalASInfo can be passed to NewStandaloneConnector.
func LoadFromTopoFile(topoFile string) (LocalASInfo, error) {
	loader, err := topology.NewLoader(
		topology.LoaderCfg{
			File:      topoFile,
			Reload:    nil,
			Validator: &topology.DefaultValidator{},
			Metrics:   newLoaderMetrics(),
		},
	)
	if err != nil {
		return nil, serrors.Wrap("creating topology loader", err)
	}
	return loader, nil
}

// newLoaderMetrics creates metrics for the topology loader.
func newLoaderMetrics() topology.LoaderMetrics {
	updates := prom.NewCounterVec(
		"", "",
		"topology_updates_total",
		"The total number of updates.",
		[]string{prom.LabelResult},
	)
	return topology.LoaderMetrics{
		ValidationErrors: metrics.NewPromCounter(updates).With(prom.LabelResult, "err_validate"),
		ReadErrors:       metrics.NewPromCounter(updates).With(prom.LabelResult, "err_read"),
		LastUpdate: metrics.NewPromGauge(
			prom.NewGaugeVec(
				"", "",
				"topology_last_update_time",
				"Timestamp of the last successful update.",
				[]string{},
			),
		),
		Updates: metrics.NewPromCounter(updates).With(prom.LabelResult, prom.Success),
	}
}
