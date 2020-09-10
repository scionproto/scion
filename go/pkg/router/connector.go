// Copyright 2020 Anapaya Systems
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

package router

import (
	"net"
	"os"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/underlay/conn"
)

// Connector implements the Dataplane API of the router control process. It sets
// up connections for the DataPlane.
type Connector struct {
	DataPlane DataPlane

	ia addr.IA
}

var errMultiIA = serrors.New("different IA not allowed")

// CreateIACtx creates the context for ISD-AS.
func (c *Connector) CreateIACtx(ia addr.IA) error {
	log.Debug("CreateIACtx", "isd_as", ia)
	if !c.ia.IsZero() {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	c.ia = ia
	return c.DataPlane.SetIA(ia)
}

// AddInternalInterface adds the internal interface.
func (c *Connector) AddInternalInterface(ia addr.IA, local net.UDPAddr) error {
	log.Debug("Adding internal interface", "isd_as", ia, "local", local)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	connection, err := conn.New(&local, nil, nil)
	if err != nil {
		return err
	}
	return c.DataPlane.AddInternalInterface(connection, local.IP)
}

// AddExternalInterface adds a link between the local and remote address.
func (c *Connector) AddExternalInterface(ia addr.IA, ifID common.IFIDType,
	local, remote net.UDPAddr, linkTo topology.LinkType, mtu int, owned bool) error {

	var bfdDisabled bool
	disabled, _ := os.LookupEnv("DISABLE_BFD")
	if disabled == "true" {
		bfdDisabled = true
	}

	log.Debug("Adding external interface",
		"isd_as", ia, "ifID", ifID, "local", local, "remote", remote, "owned", owned,
		"bfd", !bfdDisabled)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	if !owned {
		if !bfdDisabled {
			if err := c.DataPlane.AddNextHopBFD(uint16(ifID), &remote); err != nil {
				return serrors.WrapStr("adding next hop BFD", err, "if_id", ifID)
			}
		}
		return c.DataPlane.AddNextHop(uint16(ifID), &remote)
	}
	connection, err := conn.New(&local, &remote, nil)
	if err != nil {
		return err
	}
	if !bfdDisabled {
		if err := c.DataPlane.AddExternalInterfaceBFD(uint16(ifID), connection); err != nil {
			return serrors.WrapStr("adding external BFD", err, "if_id", ifID)
		}
	}
	return c.DataPlane.AddExternalInterface(uint16(ifID), connection)
}

// AddSvc adds the service address for the given ISD-AS.
func (c *Connector) AddSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	log.Debug("Adding SVC", "isd_as", ia, "svc", svc, "ip", ip)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	return c.DataPlane.AddSvc(svc, &net.IPAddr{IP: ip})
}

// DelSvc deletes the service entry for the given ISD-AS and IP pair.
func (c *Connector) DelSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	// TODO(lukedirtwalker) implement.
	log.Info("DelSVC is currently not implemented for the GoBR")
	return nil
}

// SetKey sets the key for the given ISD-AS at the given index.
func (c *Connector) SetKey(ia addr.IA, index int, key common.RawBytes) error {
	log.Debug("Setting key", "isd_as", ia, "index", index)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	if index != 0 {
		return serrors.New("currently only index 0 key is supported")
	}
	return c.DataPlane.SetKey(key)
}

// SetRevocation sets the revocation for the given ISD-AS and interface.
func (c *Connector) SetRevocation(ia addr.IA, ifID common.IFIDType, rev common.RawBytes) error {
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	// TODO(lukedirtwalker) implement.
	log.Info("SetRevocation is currently not implemented for the GoBR")
	return nil
}

// DelRevocation deletes the revocation for the given ISD-AS and interface.
func (c *Connector) DelRevocation(ia addr.IA, ifid common.IFIDType) error {
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	// TODO(lukedirtwalker) implement.
	log.Info("DelRevocation is currently not implemented for the GoBR")
	return nil
}
