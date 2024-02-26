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
	"strings"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
	api "github.com/scionproto/scion/private/mgmtapi"
	"github.com/scionproto/scion/private/topology"
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
	config.NoDefaulter
	// ID is the SCION element ID of the shim dispatcher.
	ID                     string            `toml:"id,omitempty"`
	ServiceAddresses       map[string]string `toml:"service_addresses,omitempty"`
	ParsedServiceAddresses map[addr.Addr]netip.AddrPort
	// UnderlayPort is the native port opened by the dispatcher (default 30041)
	UnderlayPort int `toml:"underlay_port,omitempty"`
}

func (cfg *Dispatcher) Validate() error {
	if cfg.UnderlayPort == 0 {
		cfg.UnderlayPort = topology.EndhostPort
	}
	if cfg.ID == "" {
		return serrors.New("id must be set")
	}

	// Process ServiceAddresses
	cfg.ParsedServiceAddresses = make(map[addr.Addr]netip.AddrPort, len(cfg.ServiceAddresses))
	for iaSvc, addr := range cfg.ServiceAddresses {
		parsedIASvc, err := parseIASvc(iaSvc)
		if err != nil {
			return serrors.WrapStr("parsing IA,SVC", err)
		}
		parsedAddr, err := netip.ParseAddrPort(addr)
		if err != nil {
			return serrors.WrapStr("parsing address", err)
		}
		cfg.ParsedServiceAddresses[parsedIASvc] = parsedAddr
	}
	return nil
}

func (cfg *Dispatcher) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(dispSample, idSample))
}

func (cfg *Dispatcher) ConfigName() string {
	return "dispatcher"
}

func parseIASvc(str string) (addr.Addr, error) {
	words := strings.Split(str, ",")
	if len(words) != 2 {
		return addr.Addr{}, serrors.New("Host addr doesn't match format \"ia, svc\"", "input", str)
	}
	ia, err := addr.ParseIA(words[0])
	if err != nil {
		return addr.Addr{}, serrors.WrapStr("parsing IA in Host addr", err)
	}
	svc, err := addr.ParseSVC(words[1])
	if err != nil {
		return addr.Addr{}, serrors.WrapStr("parsing SVC in Host addr", err)
	}
	return addr.Addr{IA: ia, Host: addr.HostSVC(svc)}, nil
}
