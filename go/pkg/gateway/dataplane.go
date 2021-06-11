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

package gateway

import (
	"net"

	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/pkg/gateway/control"
)

// DataPlaneRunner is the main point where plugging in a specific dataplane
// happens. It contains methods for creating the top-level objects and
// for starting the processing. StartIngress should be called before the other
// functions.
type DataPlaneRunner interface {
	StartIngress(scionNetwork *snet.SCIONNetwork, dataAddr *net.UDPAddr,
		deviceManager control.DeviceManager, metrics *Metrics) error
	NewDataPlaneSessionFactory(scionNetwork *snet.SCIONNetwork,
		dataClientIP net.IP, metrics *Metrics,
		reportCollector interface{}) control.DataplaneSessionFactory
	NewRoutingTableFactory() control.RoutingTableFactory
}
