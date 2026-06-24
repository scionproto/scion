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
	"gopkg.in/yaml.v3"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// Allocations is the audit record of which AS and link got which subnet. It is
// serialized to network-allocations.yml.
type Allocations struct {
	ASes  []ASRecord   `yaml:"ases"`
	Links []LinkRecord `yaml:"links"`
}

// ASRecord records the network and host addresses of one AS.
type ASRecord struct {
	ISDAS  string       `yaml:"isd_as"`
	Subnet string       `yaml:"subnet"`
	Hosts  []HostRecord `yaml:"hosts"`
}

// HostRecord records a single host's address and the elements it runs.
type HostRecord struct {
	Name     string   `yaml:"name"`
	Addr     string   `yaml:"addr"`
	Elements []string `yaml:"elements"`
}

// LinkRecord records the network and endpoint addresses of one link.
type LinkRecord struct {
	A      string `yaml:"a"`
	B      string `yaml:"b"`
	Subnet string `yaml:"subnet"`
	AddrA  string `yaml:"addr_a"`
	AddrB  string `yaml:"addr_b"`
}

// Allocations derives the audit record from the resolved network.
func (n *Network) Allocations() Allocations {
	var out Allocations
	for _, a := range n.ASes {
		rec := ASRecord{ISDAS: a.IA.String(), Subnet: a.Subnet.String()}
		for _, h := range a.Hosts {
			var elems []string
			if h.BorderRouter != nil {
				elems = append(elems, h.BorderRouter.ID)
			}
			if h.Control {
				elems = append(elems, a.Control.ID)
			}
			if h.Daemon {
				elems = append(elems, a.Daemon.ID)
			}
			rec.Hosts = append(rec.Hosts, HostRecord{
				Name:     h.Name,
				Addr:     h.Addr.String(),
				Elements: elems,
			})
		}
		out.ASes = append(out.ASes, rec)
	}
	for _, a := range n.ASes {
		for _, br := range a.BorderRouters {
			for _, intf := range br.Interfaces {
				// Record each link once, from the lower ISD-AS side.
				if a.IA.String() > intf.RemoteIA.String() {
					continue
				}
				out.Links = append(out.Links, LinkRecord{
					A:      a.IA.String(),
					B:      intf.RemoteIA.String(),
					Subnet: intf.Local.Addr().String() + " <-> " + intf.Remote.Addr().String(),
					AddrA:  intf.Local.String(),
					AddrB:  intf.Remote.String(),
				})
			}
		}
	}
	return out
}

// Marshal renders the allocations as YAML.
func (a Allocations) Marshal() ([]byte, error) {
	raw, err := yaml.Marshal(a)
	if err != nil {
		return nil, serrors.Wrap("marshaling allocations", err)
	}
	return raw, nil
}
