// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"io"
	"net"
	"strconv"

	"github.com/scionproto/scion/go/lib/config"
)

// Defaults.
const (
	DefaultCtrlAddr = ":30256"
	DefaultDataAddr = ":30056"
	defaultCtrlPort = 30256
	defaultDataPort = 30056

	DefaultTunnelName           = "sig"
	DefaultTunnelRoutingTableID = 11
)

// Gateway holds the gateway specific configuration.
type Gateway struct {
	config.NoDefaulter

	// ID of the SIG.
	ID string `toml:"id,omitempty"`
	// TrafficPolicy is the file path of the traffic policy file.
	TrafficPolicy string `toml:"traffic_policy_file,omitempty"`
	// IPRoutingPolicy is the file path of the IP routing policy file.
	IPRoutingPolicy string `toml:"ip_routing_policy_file,omitempty"`
	// Control plane address, for prefix discovery.
	CtrlAddr string `toml:"ctrl_addr,omitempty"`
	// Data plane address, for frames.
	DataAddr string `toml:"data_addr,omitempty"`
}

func (cfg *Gateway) Validate() error {
	if cfg.ID == "" {
		cfg.ID = "gateway"
	}
	if cfg.TrafficPolicy == "" {
		cfg.TrafficPolicy = DefaultSessionPoliciesFile
	}
	cfg.CtrlAddr = DefaultAddress(cfg.CtrlAddr, defaultCtrlPort)
	cfg.DataAddr = DefaultAddress(cfg.DataAddr, defaultDataPort)
	return nil
}

func (cfg *Gateway) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, gatewaySample)
}

func (cfg *Gateway) ConfigName() string {
	return "gateway"
}

// Tunnel holds the tunneling configuration.
type Tunnel struct {
	config.NoDefaulter

	// Name is the name of TUN device to create.
	Name string `toml:"name,omitempty"`
	// RoutingTableID is the ID of the routing table used in the gateway.
	RoutingTableID int `toml:"routing_table_id,omitempty"`
	// SrcIPv4 is the source address int to put into the routing table.
	SrcIPv4 net.IP `toml:"src_ipv4,omitempty"`
	// SrcIPv6 is the source address int to put into the routing table.
	SrcIPv6 net.IP `toml:"src_ipv6,omitempty"`
}

func (cfg *Tunnel) Validate() error {
	if cfg.Name == "" {
		cfg.Name = DefaultTunnelName
	}
	if cfg.RoutingTableID == 0 {
		cfg.RoutingTableID = DefaultTunnelRoutingTableID
	}
	return nil
}

func (cfg *Tunnel) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, tunnelSample)
}

func (cfg *Tunnel) ConfigName() string {
	return "tunnel"
}

// DefaultAddress determines the default address. If port is not specified, or
// is zero, it is set to the default port. If the input is garbage, the output
// is garbage as well.
func DefaultAddress(input string, defaultPort int) string {
	host, port, err := net.SplitHostPort(input)
	switch {
	case err != nil:
		return net.JoinHostPort(input, strconv.Itoa(defaultPort))
	case port == "0", port == "":
		return net.JoinHostPort(host, strconv.Itoa(defaultPort))
	default:
		return input
	}
}
