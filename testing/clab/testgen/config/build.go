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

// Package config builds the generalized per-host configuration (clabconfig.Config)
// and the shared per-AS topology.json from a resolved [hydrate.Network].
package config

import (
	"net/netip"
	"sort"

	"github.com/scionproto/scion/pkg/segment/iface"
	topojson "github.com/scionproto/scion/private/topology/json"
	clabconfig "github.com/scionproto/scion/testing/clab/cmd/controller/config"
	"github.com/scionproto/scion/testing/clab/testgen/hydrate"
)

// endhostPortRange is the dispatched-port range advertised in topology.json.
const endhostPortRange = "1024-65535"

// HostConfig builds the generalized configuration for a single host.
func HostConfig(a *hydrate.AS, h *hydrate.Host) clabconfig.Config {
	as := clabconfig.AS{
		ISDAS: a.IA,
		Core:  a.Attrs.Core,
		MTU:   a.MTU,
	}
	// eth0 is the containerlab management interface (carries the host's
	// AS-internal address); only the inter-AS data-plane links (eth1, eth2, …)
	// are modeled here.
	var ifs clabconfig.Interfaces

	if br := h.BorderRouter; br != nil {
		as.Router = &clabconfig.Router{
			ID:                br.ID,
			InternalInterface: br.InternalAddr,
			APIAddr:           br.APIAddr,
			SCIONMTU:          a.MTU,
		}
		as.Neighbors = neighbors(br)
		for _, intf := range br.Interfaces {
			ifs.Ethernets = append(ifs.Ethernets, clabconfig.Ethernet{
				Name:      intf.EthName,
				Addresses: []string{cidr(intf.Local.Addr(), intf.Net.Bits())},
				MTU:       intf.MTU,
			})
		}
	}
	if h.Control {
		as.Control = &clabconfig.Control{
			ID:      a.Control.ID,
			Address: a.Control.Addr,
			APIAddr: a.Control.API,
			Issuing: a.Attrs.Issuing,
		}
	}
	if h.Daemon {
		as.Daemon = &clabconfig.Daemon{
			ID:      a.Daemon.ID,
			Address: a.Daemon.Addr,
			APIAddr: a.Daemon.API,
		}
	}
	return clabconfig.Config{
		SCION:      clabconfig.SCION{ASes: []clabconfig.AS{as}},
		Interfaces: ifs,
	}
}

// neighbors groups a border router's interfaces by neighboring AS.
func neighbors(br *hydrate.BorderRouter) []clabconfig.Neighbor {
	order := []string{}
	byIA := map[string]*clabconfig.Neighbor{}
	for _, intf := range br.Interfaces {
		key := intf.RemoteIA.String()
		n, ok := byIA[key]
		if !ok {
			order = append(order, key)
			byIA[key] = &clabconfig.Neighbor{
				ISDAS:        intf.RemoteIA,
				Relationship: clabconfig.LinkType(intf.LinkType),
			}
			n = byIA[key]
		}
		n.Interfaces = append(n.Interfaces, clabconfig.Interface{
			ID:       uint64(intf.IfID),
			Underlay: string(intf.Underlay),
			Address:  intf.Local,
			Remote:   clabconfig.Remote{Address: intf.Remote, ID: uint64(intf.RemoteIfID)},
			MTU:      intf.MTU,
		})
	}
	sort.Strings(order)
	out := make([]clabconfig.Neighbor, 0, len(order))
	for _, k := range order {
		out = append(out, *byIA[k])
	}
	return out
}

// Topology builds the AS-wide topology.json shared by all the AS's hosts.
func Topology(a *hydrate.AS) *topojson.Topology {
	t := &topojson.Topology{
		IA:               a.IA.String(),
		MTU:              a.MTU,
		EndhostPortRange: endhostPortRange,
		BorderRouters:    map[string]*topojson.BRInfo{},
		ControlService:   map[string]*topojson.ServerInfo{},
		DiscoveryService: map[string]*topojson.ServerInfo{},
	}
	if a.Attrs.Core {
		t.Attributes = topojson.Attributes{topojson.AttrCore}
	}
	for _, br := range a.BorderRouters {
		info := &topojson.BRInfo{
			InternalAddr: br.InternalAddr.String(),
			Interfaces:   map[iface.ID]*topojson.BRInterface{},
		}
		for _, intf := range br.Interfaces {
			info.Interfaces[intf.IfID] = &topojson.BRInterface{
				Underlay: topojson.Underlay{
					Local:  intf.Local.String(),
					Remote: intf.Remote.String(),
				},
				IA:         intf.RemoteIA.String(),
				LinkTo:     string(intf.LinkType),
				MTU:        intf.MTU,
				RemoteIfID: intf.RemoteIfID,
			}
		}
		t.BorderRouters[br.ID] = info
	}
	t.ControlService[a.Control.ID] = &topojson.ServerInfo{Addr: a.Control.Addr.String()}
	t.DiscoveryService[a.Control.ID] = &topojson.ServerInfo{Addr: a.Control.Addr.String()}
	return t
}

// cidr formats an address with the given prefix length.
func cidr(a netip.Addr, bits int) string {
	return netip.PrefixFrom(a, bits).String()
}
