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

// Package clab generates a containerlab topology from a resolved network, plus
// the per-host network.yaml the clab-node controller consumes
// (testing/clab/controller). Each containerlab node is one host; an AS's hosts
// share the management network (their static management IP is the host's
// AS-internal address), which provides intra-AS connectivity. Inter-AS links
// are dedicated containerlab veth links between the hosts' data-plane
// interfaces (eth1, eth2, …).
package clab

import (
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/tools/testgen/hydrate"
	"github.com/scionproto/scion/tools/testgen/out"
)

const nodeImage = "scion/clab-node:latest"

// Options configures clab generation.
type Options struct {
	// LabName is the containerlab lab name.
	LabName string
	// MgmtV4 is the IPv4 management subnet (must contain every AS's v4 subnet).
	MgmtV4 netip.Prefix
	// MgmtV6 is the IPv6 management subnet; the zero value disables IPv6 mgmt.
	MgmtV6 netip.Prefix
}

// Generate writes the containerlab topology file and the per-host network.yaml
// files.
func Generate(network *hydrate.Network, dir out.Dir, opts Options, w io.Writer) error {
	topo, err := buildTopology(network, dir, opts)
	if err != nil {
		return err
	}
	raw, err := yaml.Marshal(topo)
	if err != nil {
		return serrors.Wrap("marshaling clab topology", err)
	}
	if err := out.WriteFile(dir.Clab(opts.LabName), raw); err != nil {
		return err
	}
	if err := writeNetworkConfigs(network, dir); err != nil {
		return err
	}
	fmt.Fprintf(w, "clab: wrote %s\n", dir.Clab(opts.LabName))
	return nil
}

// clabTopology mirrors the subset of the containerlab schema we emit.
type clabTopology struct {
	Name     string    `yaml:"name"`
	Mgmt     *mgmt     `yaml:"mgmt,omitempty"`
	Topology topoBlock `yaml:"topology"`
}

type mgmt struct {
	Network    string `yaml:"network"`
	IPv4Subnet string `yaml:"ipv4-subnet,omitempty"`
	IPv6Subnet string `yaml:"ipv6-subnet,omitempty"`
}

type topoBlock struct {
	Defaults nodeDefaults     `yaml:"defaults"`
	Nodes    map[string]*node `yaml:"nodes"`
	Links    []link           `yaml:"links"`
}

type nodeDefaults struct {
	Kind  string `yaml:"kind"`
	Image string `yaml:"image"`
}

type node struct {
	MgmtIPv4 string            `yaml:"mgmt-ipv4,omitempty"`
	MgmtIPv6 string            `yaml:"mgmt-ipv6,omitempty"`
	Env      map[string]string `yaml:"env,omitempty"`
	Binds    []string          `yaml:"binds,omitempty"`
}

type link struct {
	Endpoints []string `yaml:"endpoints"`
}

func buildTopology(network *hydrate.Network, dir out.Dir, opts Options) (*clabTopology, error) {
	t := &clabTopology{
		Name: opts.LabName,
		Mgmt: &mgmt{Network: opts.LabName + "-mgmt"},
		Topology: topoBlock{
			Defaults: nodeDefaults{Kind: "linux", Image: nodeImage},
			Nodes:    map[string]*node{},
		},
	}
	if opts.MgmtV4.IsValid() {
		t.Mgmt.IPv4Subnet = opts.MgmtV4.String()
	}
	if opts.MgmtV6.IsValid() {
		t.Mgmt.IPv6Subnet = opts.MgmtV6.String()
	}

	for _, as := range network.ASes {
		for _, host := range as.Hosts {
			n, err := buildNode(as, host, dir)
			if err != nil {
				return nil, err
			}
			t.Topology.Nodes[nodeName(as.IA, host.Name)] = n
		}
	}
	t.Topology.Links = buildLinks(network)
	return t, nil
}

func buildNode(as *hydrate.AS, host *hydrate.Host, dir out.Dir) (*node, error) {
	hostRel, err := filepath.Rel(dir.Base(), dir.Host(as.IA, host.Name))
	if err != nil {
		return nil, serrors.Wrap("computing host bind path", err)
	}
	cryptoRel, err := filepath.Rel(dir.Base(), filepath.Join(dir.AS(as.IA), "crypto"))
	if err != nil {
		return nil, serrors.Wrap("computing crypto bind path", err)
	}
	keysRel, err := filepath.Rel(dir.Base(), filepath.Join(dir.AS(as.IA), "keys"))
	if err != nil {
		return nil, serrors.Wrap("computing keys bind path", err)
	}
	n := &node{
		Env: map[string]string{"SCION_NETWORK_CONFIG": "/etc/scion/network.yaml"},
		Binds: []string{
			hostRel + ":/etc/scion:rw",
			cryptoRel + ":/etc/scion/crypto:ro",
			keysRel + ":/etc/scion/keys:ro",
			"trcs:/etc/scion/certs:ro",
		},
	}
	if host.Addr.Is6() {
		n.MgmtIPv6 = host.Addr.String()
	} else {
		n.MgmtIPv4 = host.Addr.String()
	}
	return n, nil
}

// buildLinks emits one containerlab link per inter-AS link, pairing the two
// border-router data-plane interfaces. Each link is emitted once, keyed off the
// lexicographically smaller endpoint.
func buildLinks(network *hydrate.Network) []link {
	type endpoint struct{ node, eth string }
	index := map[ifaceKey]endpoint{}
	for _, as := range network.ASes {
		for _, br := range as.BorderRouters {
			for _, intf := range br.Interfaces {
				index[ifaceKey{as.IA, uint64(intf.IfID)}] = endpoint{
					node: nodeName(as.IA, br.Host),
					eth:  intf.EthName,
				}
			}
		}
	}

	var links []link
	for _, as := range network.ASes {
		for _, br := range as.BorderRouters {
			for _, intf := range br.Interfaces {
				local := ifaceKey{as.IA, uint64(intf.IfID)}
				remote := ifaceKey{intf.RemoteIA, uint64(intf.RemoteIfID)}
				if local.less(remote) {
					a := index[local]
					b := index[remote]
					links = append(links, link{Endpoints: []string{
						a.node + ":" + a.eth,
						b.node + ":" + b.eth,
					}})
				}
			}
		}
	}
	sort.Slice(links, func(i, j int) bool {
		return links[i].Endpoints[0] < links[j].Endpoints[0]
	})
	return links
}

type ifaceKey struct {
	ia   addr.IA
	ifID uint64
}

func (k ifaceKey) less(o ifaceKey) bool {
	if k.ia != o.ia {
		return k.ia.String() < o.ia.String()
	}
	return k.ifID < o.ifID
}

// nodeName is the containerlab node name for a host: the AS in file format
// followed by the host name, e.g. "1-ff00_0_110-host-1".
func nodeName(ia addr.IA, host string) string {
	return fmt.Sprintf("%s-%s", addr.FormatIA(ia, addr.WithFileSeparator()), host)
}

// networkConfig is the controller's interface-addressing file (see
// testing/clab/controller). Only the inter-AS data-plane interfaces are listed;
// eth0 (management) is configured by containerlab.
type networkConfig struct {
	Config struct {
		Interfaces struct {
			Ethernets []ethernet `yaml:"ethernets"`
		} `yaml:"interfaces"`
	} `yaml:"config"`
}

type ethernet struct {
	Name      string   `yaml:"name"`
	Addresses []string `yaml:"addresses"`
}

func writeNetworkConfigs(network *hydrate.Network, dir out.Dir) error {
	for _, as := range network.ASes {
		for _, host := range as.Hosts {
			var cfg networkConfig
			if br := host.BorderRouter; br != nil {
				for _, intf := range br.Interfaces {
					cfg.Config.Interfaces.Ethernets = append(
						cfg.Config.Interfaces.Ethernets,
						ethernet{
							Name: intf.EthName,
							Addresses: []string{
								netip.PrefixFrom(intf.Local.Addr(), intf.Net.Bits()).String(),
							},
						},
					)
				}
			}
			raw, err := yaml.Marshal(cfg)
			if err != nil {
				return serrors.Wrap("marshaling network config", err, "host", host.Name)
			}
			path := filepath.Join(dir.Host(as.IA, host.Name), "network.yaml")
			if err := out.WriteFile(path, raw); err != nil {
				return err
			}
		}
	}
	return nil
}
