// Copyright 2017 ETH Zurich
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

package base

import (
	"net"

	"github.com/vishvananda/netlink"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/sig/xnet"
)

type NetEntry struct {
	Net   *net.IPNet
	Route *netlink.Route
}

func newNetEntry(link netlink.Link, ipnet *net.IPNet) (*NetEntry, error) {
	ne := &NetEntry{Net: ipnet, Route: xnet.NewRoute(link, ipnet)}
	return ne, ne.setup()
}

func (ne *NetEntry) setup() error {
	if err := netlink.RouteAdd(ne.Route); err != nil {
		return common.NewCError("Unable to add route for remote network",
			"route", ne.Route, "err", err)
	}
	return nil
}

func (ne *NetEntry) Cleanup() error {
	if err := netlink.RouteDel(ne.Route); err != nil {
		return common.NewCError("Unable to delete route for remote network",
			"route", ne.Route, "err", err)
	}
	return nil
}
