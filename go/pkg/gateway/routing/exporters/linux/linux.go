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

package linux

import (
	"net"

	"github.com/vishvananda/netlink"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/pkg/gateway/xnet"
)

// RouteExporter adds routes to the main Linux routing table.
type RouteExporter struct {
	// Device is the Linux device for the route.
	Device netlink.Link
	// Source is the source IP address for locally-originated packets that leave
	// the local host through the route.
	Source net.IP
}

// AddNetwork will add a route to network in the main Linux routing table.
func (rt RouteExporter) AddNetwork(network net.IPNet) {
	if err := xnet.AddRoute(0, rt.Device, &network, rt.Source); err != nil {
		log.Info("Unable to add route", "err", err, "route", network)
		return
	}
	log.Info("Added route", "route", network)
}

// DeleteNetwork will delete the route to network from the main Linux routing table.
func (rt RouteExporter) DeleteNetwork(network net.IPNet) {
	if err := xnet.DeleteRoute(0, rt.Device, &network, rt.Source); err != nil {
		log.Info("Unable to delete route", "err", err, "route", network)
		return
	}
	log.Info("Deleted route", "route", network)
}
