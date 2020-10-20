// Copyright 2018 Anapaya Systems
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

package config

import (
	"io"
	"net"
	"strconv"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

const (
	DefaultCtrlAddr = ":30256"
	DefaultDataAddr = ":30056"
	defaultCtrlPort = 30256
	defaultDataPort = 30056

	DefaultTrafficPolicyFile = "/share/conf/traffic.policy"

	DefaultTunnelName           = "sig"
	DefaultTunnelRoutingTableID = 11
)

type Config struct {
	Features env.Features
	Logging  log.Config       `toml:"log,omitempty"`
	Metrics  env.Metrics      `toml:"metrics,omitempty"`
	Daemon   env.SCIONDClient `toml:"sciond_connection,omitempty"`
	Gateway  Gateway          `toml:"gateway,omitempty"`
	Tunnel   Tunnel           `toml:"tunnel,omitempty"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Daemon,
		&cfg.Gateway,
		&cfg.Tunnel,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Daemon,
		&cfg.Gateway,
		&cfg.Tunnel,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: "gateway"},
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Daemon,
		&cfg.Gateway,
		&cfg.Tunnel,
	)
}

// Gateway holds the gateway specific configuration.
type Gateway struct {
	config.NoDefaulter

	// ID of the SIG.
	ID string `toml:"id,omitempty"`
	// TrafficPolicy is the file path of the traffic policy file.
	TrafficPolicy string `toml:"traffic_policy_file,omitempty"`
	// Control plane address, for probes.
	CtrlAddr string `toml:"ctrl_addr,omitempty"`
	// Data plane address, for frames.
	DataAddr string `toml:"data_addr,omitempty"`
	// SCION dispatcher path.
	Dispatcher string `toml:"dispatcher,omitempty"`
}

func (cfg *Gateway) Validate() error {
	if cfg.ID == "" {
		cfg.ID = "gateway"
	}
	if cfg.TrafficPolicy == "" {
		return serrors.New("traffic_policy_file must be set")
	}
	cfg.CtrlAddr = defaultAddress(cfg.CtrlAddr, defaultCtrlPort)
	cfg.DataAddr = defaultAddress(cfg.DataAddr, defaultDataPort)

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

// defaultAddress determines the default address. If port is not specified, or
// is zero, it is set to the default port. If the input is garbage, the output
// is garbage as well.
func defaultAddress(input string, defaultPort int) string {
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
