// Copyright 2018 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

// Package config contains the configuration of the SCION dispatcher.
package config

import (
	"fmt"
	"io"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
	api "github.com/scionproto/scion/private/mgmtapi"
)

var _ config.Config = (*Config)(nil)

type Config struct {
	Features   env.Features `toml:"features,omitempty"`
	Logging    log.Config   `toml:"log,omitempty"`
	Metrics    env.Metrics  `toml:"metrics,omitempty"`
	API        api.Config   `toml:"api,omitempty"`
	Dispatcher Dispatcher   `toml:"dispatcher,omitempty"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Dispatcher,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Dispatcher,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Dispatcher,
	)
}

func (cfg *Config) ConfigName() string {
	return "dispatcher_config"
}

// Dispatcher contains the dispatcher specific config.
type Dispatcher struct {
	// ID is the SCION element ID of the shim dispatcher.
	ID string `toml:"id,omitempty"`
	// LocalUDPForwarding specifies whether UDP forwarding is enabled for the dispatcher.
	// Otherwise, it will only reply to SCMPInfo packets.
	LocalUDPForwarding bool `toml:"local_udp_forwarding,omitempty"`
	// ServiceAddresses is the map of IA,SVC -> underlay UDP/IP address.
	// The map should be configured provided that the shim dispatcher runs colocated to such
	// mapped services, e.g., the shim dispatcher runs on the same host,
	//  where the CS for the local IA runs.
	ServiceAddresses map[addr.Addr]netip.AddrPort `toml:"service_addresses,omitempty"`
	// UnderlayAddr is the IP address where the shim dispatcher listens on (default ::).
	UnderlayAddr netip.Addr `toml:"underlay_addr,omitempty"`
}

func (cfg *Dispatcher) InitDefaults() {
	if cfg.UnderlayAddr == (netip.Addr{}) {
		cfg.UnderlayAddr = netip.IPv6Unspecified()
	}
}

func (cfg *Dispatcher) Validate() error {
	if !cfg.UnderlayAddr.IsValid() {
		return serrors.New("underlay_addr is not set or it is incorrect")
	}
	if cfg.ID == "" {
		return serrors.New("id must be set")
	}

	// Process ServiceAddresses
	for iaSVC := range cfg.ServiceAddresses {
		if iaSVC.Host.Type() != addr.HostTypeSVC {
			return serrors.New("parsed address must be SVC", "type", iaSVC.Host.Type().String())
		}
	}
	return nil
}

func (cfg *Dispatcher) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(dispSample, idSample))
}

func (cfg *Dispatcher) ConfigName() string {
	return "dispatcher"
}
