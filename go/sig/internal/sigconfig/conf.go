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
)

const (
	DefaultCtrlPort    = 10081
	DefaultEncapPort   = 10080
	DefaultTunName     = "sig"
	DefaultTunRTableId = 11
)

// Conf contains the configuration specific to the SIG.
type Conf struct {
	// ID of the SIG (required)
	ID string
	// The SIG config json file. (required)
	SIGConfig string
	// IA the local IA (required)
	IA addr.IA
	// IP the bind IP address (required)
	IP net.IP
	// Control data port, e.g. keepalives. (default DefaultCtrlPort)
	CtrlPort uint16
	// Encapsulation data port. (default DefaultEncapPort)
	EncapPort uint16
	// SCION dispatcher path. (default "")
	Dispatcher string
	// Name of TUN device to create. (default DefaultTunName)
	Tun string
	// TunRTableId the id of the routing table used in the SIG. (default DefaultTunRTableId)
	TunRTableId int
	// IPv4 source address hint to put into routing table.
	SrcIP4 net.IP
	// IPv6 source address hint to put into routing table.
	SrcIP6 net.IP
}

// Validate validate the config and returns an error if a value is not valid.
func (c Conf) Validate() error {
	if c.ID == "" {
		return common.NewBasicError("ID must be set!", nil)
	}
	if c.SIGConfig == "" {
		return common.NewBasicError("Config must be set!", nil)
	}
	if c.IA.IsZero() {
		return common.NewBasicError("IA must be set", nil)
	}
	if c.IA.IsWildcard() {
		return common.NewBasicError("Wildcard IA not allowed", nil)
	}
	if c.IP.IsUnspecified() {
		return common.NewBasicError("IP must be set", nil)
	}
	return nil
}

// InitDefaults sets the default values to unset values.
func (c *Conf) InitDefaults() {
	if c.CtrlPort == 0 {
		c.CtrlPort = DefaultCtrlPort
	}
	if c.EncapPort == 0 {
		c.EncapPort = DefaultEncapPort
	}
	if c.Tun == "" {
		c.Tun = DefaultTunName
	}
	if c.TunRTableId == 0 {
		c.TunRTableId = DefaultTunRTableId
	}
}
