// Copyright 2026 Anapaya Systems
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

package hydrate

import (
	"fmt"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// maxIfNameLen is the maximum length of a Linux interface name (IFNAMSIZ - 1).
const maxIfNameLen = 15

// HostLink is a point-to-point link between an AS's host-1 node and the machine
// running the lab. It gives processes on that machine a dedicated address
// inside the AS: the border router on host-1 delivers SCION packets for
// HostAddr over the link, so a SCION application on the machine can bind to it.
type HostLink struct {
	// EthName is the node-side interface name (e.g. "eth3").
	EthName string
	// HostIface is the machine-side interface name, in the machine's network
	// namespace (e.g. "1-ff00_0_110").
	HostIface string
	// Net is the link's network.
	Net netip.Prefix
	// NodeAddr is the node-side address.
	NodeAddr netip.Addr
	// HostAddr is the machine-side address that applications bind to.
	HostAddr netip.Addr
}

// AddHostLinks attaches a [HostLink] to the first host (host-1) of every AS.
// host-1 runs the control service and the daemon, and the border router of
// the default link group if the AS has one. The link's address family follows
// the AS underlay, so it matches the family of the AS's border router internal
// addresses.
func AddHostLinks(n *Network, alloc Allocator) error {
	for i, a := range n.ASes {
		la, err := alloc.HostLink(a.IA, a.Underlay)
		if err != nil {
			return serrors.Wrap("allocating host link", err, "as", a.IA)
		}
		h := a.Hosts[0]
		// eth0 is the management interface, eth1..ethN are the border router's
		// inter-AS interfaces; the host link takes the next free one.
		eth := 1
		if h.BorderRouter != nil {
			eth += len(h.BorderRouter.Interfaces)
		}
		h.HostLink = &HostLink{
			EthName:   fmt.Sprintf("eth%d", eth),
			HostIface: hostIfaceName(a.IA, i),
			Net:       la.Subnet,
			NodeAddr:  la.A,
			HostAddr:  la.B,
		}
	}
	return nil
}

// hostIfaceName is the machine-side interface name of an AS's host link: the
// ISD-AS in file format (e.g. "1-ff00_0_110"), or "scion-as<index>" if that
// does not fit into a Linux interface name.
func hostIfaceName(ia addr.IA, index int) string {
	name := addr.FormatIA(ia, addr.WithFileSeparator())
	if len(name) > maxIfNameLen {
		name = fmt.Sprintf("scion-as%d", index)
	}
	return name
}
