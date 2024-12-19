// Copyright 2021 Anapaya Systems
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

// Package env contains host-wide SCION settings. Contents will most likely be populated by reading
// a well-known file on the host, e.g., /etc/scion/environment.json.
package env

import (
	"net"
	"strconv"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// SCION is the top-level object containing the host-wide SCION environment settings.
type SCION struct {
	// General contains general, AS-independent host-wide SCION settings.
	General General `json:"general,omitempty"`
	// ASes contains AS-specific host-wide SCION settings.
	ASes map[addr.IA]AS `json:"ases,omitempty"`
}

func (s *SCION) Validate() error {
	if err := s.General.Validate(); err != nil {
		return err
	}
	for ia, as := range s.ASes {
		if err := as.Validate(); err != nil {
			return serrors.Wrap("validating AS", err, "isd-as", ia)
		}
	}
	return nil
}

// General contains general, AS-independent host-wide SCION settings.
type General struct {
	// DefaultIA is the ISD-AS that will be used by default as a source AS in case multiple SCION
	// ASes are available on the host.
	DefaultIA addr.IA `json:"default_isd_as,omitempty"`
}

func (g *General) Validate() error {
	if !g.DefaultIA.IsZero() && g.DefaultIA.IsWildcard() {
		return serrors.New("default isd-as cannot be a wildcard")
	}
	return nil
}

type AS struct {
	// DaemonAddress is the address of the SCION Daemon API endpoint.
	DaemonAddress string `json:"daemon_address,omitempty"`
}

func (a *AS) Validate() error {
	if a.DaemonAddress == "" {
		return nil
	}
	ipStr, portStr, err := net.SplitHostPort(a.DaemonAddress)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(ipStr); ip != nil && ip.IsUnspecified() {
		return serrors.New("cannot use wildcard address")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return err
	}
	if port == 0 {
		return serrors.New("daemon port cannot be 0")
	}
	return nil
}
