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

package sigconfig

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sciond"
)

const (
	DefaultCtrlPort  = 10081
	DefaultEncapPort = 10080
	DefaultTunName   = "sig"
)

// Conf contains the configuration specific to the SIG.
type Conf struct {
	// ID of the SIG (Required.)
	ID string
	// The SIG config json file. (Required.)
	Config string
	// IA the local IA (Required.)
	IA addr.IA
	// IP the bind IP address (Required.)
	IP net.IP
	// Control data port, e.g. keepalives. (Default: DefaultCtrlPort)
	CtrlPort uint16
	// Encapsulation data port. (Default: DefaultEncapPort)
	EncapPort uint16
	// SCIOND socket path. (Default: default sciond path)
	Sciond string
	// SCION dispatcher path. (Default: "")
	Dispatcher string
	// Name of TUN device to create. (Default: DefaultTunName)
	Tun string
}

// Validate validate the config and returns an error if a value is not valid.
func (c Conf) Validate() error {
	if c.ID == "" {
		return common.NewBasicError("ID must be set!", nil)
	}
	if c.Config == "" {
		return common.NewBasicError("Config must be set!", nil)
	}
	if c.IA.IsZero() {
		return common.NewBasicError("IA must be set", nil)
	}
	if c.IP.IsUnspecified() {
		return common.NewBasicError("IP must be set", nil)
	}
	return nil
}

// InitDefaults sets the default values to unset values.
func (c *Conf) InitDefaults() {
	// TODO(lukedirtwalker): We should differ between "zero-values" and not set.
	// This could be done using the MetaData from the TOML parse.
	if c.CtrlPort == 0 {
		c.CtrlPort = DefaultCtrlPort
	}
	if c.EncapPort == 0 {
		c.EncapPort = DefaultEncapPort
	}
	if c.Sciond == "" {
		c.Sciond = sciond.GetDefaultSCIONDPath(nil)
	}
	if c.Tun == "" {
		c.Tun = DefaultTunName
	}
}
