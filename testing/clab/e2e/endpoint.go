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

// Package e2e holds the shared building blocks for the containerlab
// end-to-end tests (e2e_scion, e2e_http, await_connectivity): discovery of the
// generated lab, the docker-exec helper, the progress bar, and the
// source×destination result matrix.
package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"gopkg.in/yaml.v3"
)

// DaemonAPIPort is the SCION daemon client API port (pkg/daemon.DefaultAPIPort).
const DaemonAPIPort = 30255

// Endpoint is one AS as seen by the test driver: which container hosts its
// control plane and daemon, and the underlay IP to reach them.
type Endpoint struct {
	// IA is the ISD-AS string, e.g. "1-ff00:0:110".
	IA string
	// Container is the docker container running this AS's control service and
	// daemon (the host that runs sciond).
	Container string
	// Host is the underlay IP of that container (its management address). It is
	// both the sciond host and the destination reached by other ASes.
	Host string
}

// SCIONAddr renders the SCION address of this endpoint for the `scion` CLI:
// "1-ff00:0:110,10.0.1.1" / "1-ff00:0:110,fd00::1". The host part is parsed
// directly as an IP, so IPv6 is NOT bracketed.
func (e Endpoint) SCIONAddr() string {
	return e.IA + "," + e.Host
}

// SciondAddr renders the daemon address for the --sciond flag, an IP:Port that
// brackets IPv6 hosts: "10.0.1.1:30255" / "[fd00::1]:30255".
func (e Endpoint) SciondAddr() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(DaemonAPIPort))
}

// ListenAddr is the server's underlay listen address for the given port.
func (e Endpoint) ListenAddr(port int) string {
	return net.JoinHostPort(e.Host, strconv.Itoa(port))
}

// RemoteAddr is the SCION UDP address other ASes use to reach this AS's server.
func (e Endpoint) RemoteAddr(port int) string {
	return fmt.Sprintf("%s,%s", e.IA, net.JoinHostPort(e.Host, strconv.Itoa(port)))
}

// clabFile is the subset of the containerlab topology we parse.
type clabFile struct {
	Name     string `yaml:"name"`
	Topology struct {
		Nodes map[string]struct {
			MgmtIPv4 string `yaml:"mgmt-ipv4"`
			MgmtIPv6 string `yaml:"mgmt-ipv6"`
		} `yaml:"nodes"`
	} `yaml:"topology"`
}

// LoadEndpoints derives the per-AS endpoints from the generated lab: it reads
// the clab topology (node names + management IPs) and sciond_addresses.json
// (ISD-AS -> control host IP), and matches each AS to the container whose
// management IP is that AS's control host (the one running sciond).
func LoadEndpoints(genDir, lab string) ([]Endpoint, error) {
	clabRaw, err := os.ReadFile(filepath.Join(genDir, lab+".clab.yml"))
	if err != nil {
		return nil, fmt.Errorf("reading clab topology: %w", err)
	}
	var topo clabFile
	if err := yaml.Unmarshal(clabRaw, &topo); err != nil {
		return nil, fmt.Errorf("parsing clab topology: %w", err)
	}

	sciondRaw, err := os.ReadFile(filepath.Join(genDir, "sciond_addresses.json"))
	if err != nil {
		return nil, fmt.Errorf("reading sciond addresses: %w", err)
	}
	var sciond map[string]string
	if err := json.Unmarshal(sciondRaw, &sciond); err != nil {
		return nil, fmt.Errorf("parsing sciond addresses: %w", err)
	}

	// Index nodes by management IP so we can find the control container for an
	// AS from its sciond host address.
	nodeByIP := make(map[string]string, len(topo.Topology.Nodes))
	for name, n := range topo.Topology.Nodes {
		if n.MgmtIPv4 != "" {
			nodeByIP[n.MgmtIPv4] = name
		}
		if n.MgmtIPv6 != "" {
			nodeByIP[n.MgmtIPv6] = name
		}
	}

	ias := make([]string, 0, len(sciond))
	for ia := range sciond {
		ias = append(ias, ia)
	}
	sort.Strings(ias)

	eps := make([]Endpoint, 0, len(ias))
	for _, ia := range ias {
		host := sciond[ia]
		node, ok := nodeByIP[host]
		if !ok {
			return nil, fmt.Errorf("no clab node with management IP %s (AS %s)", host, ia)
		}
		eps = append(eps, Endpoint{
			IA:        ia,
			Container: fmt.Sprintf("clab-%s-%s", topo.Name, node),
			Host:      host,
		})
	}
	return eps, nil
}
