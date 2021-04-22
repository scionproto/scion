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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/underlay/conn"
	"github.com/scionproto/scion/go/pkg/router/control"
)

// receiveBufferSize is the size of receive buffers used by the router.
const receiveBufferSize = 1 << 20

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
	connection, err := conn.New(&local, nil,
		&conn.Config{ReceiveBufferSize: receiveBufferSize})
	if err != nil {
		return err
	}
	return c.DataPlane.AddInternalInterface(connection, local.IP)
}

// AddExternalInterface adds a link between the local and remote address.
func (c *Connector) AddExternalInterface(localIfID common.IFIDType, link control.LinkInfo,
	owned bool) error {

	intf := uint16(localIfID)
	log.Debug("Adding external interface", "interface", localIfID,
		"local_isd_as", link.Local.IA, "local_addr", link.Local.Addr,
		"remote_isd_as", link.Remote.IA, "remote_addr", link.Remote.IA,
		"owned", owned, "bfd", !link.BFD.Disable)

	if !c.ia.Equal(link.Local.IA) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", link.Local.IA)
	}
	if err := c.DataPlane.AddLinkType(intf, link.LinkTo); err != nil {
		return serrors.WrapStr("adding link type", err, "if_id", localIfID)
	}
	if err := c.DataPlane.AddNeighborIA(intf, link.Remote.IA); err != nil {
		return serrors.WrapStr("adding neighboring IA", err, "if_id", localIfID)
	}

	if !owned {
		if !link.BFD.Disable {
			err := c.DataPlane.AddNextHopBFD(intf, link.Local.Addr, link.Remote.Addr,
				link.BFD, link.Instance)
			if err != nil {
				return serrors.WrapStr("adding next hop BFD", err, "if_id", localIfID)
			}
		}
		return c.DataPlane.AddNextHop(intf, link.Remote.Addr)
	}
	connection, err := conn.New(link.Local.Addr, link.Remote.Addr,
		&conn.Config{ReceiveBufferSize: receiveBufferSize})
	if err != nil {
		return err
	}
	if !link.BFD.Disable {
		err := c.DataPlane.AddExternalInterfaceBFD(intf, connection, link.Local,
			link.Remote, link.BFD)
		if err != nil {
			return serrors.WrapStr("adding external BFD", err, "if_id", localIfID)
		}
	}
	return c.DataPlane.AddExternalInterface(intf, connection)
}

// AddSvc adds the service address for the given ISD-AS.
func (c *Connector) AddSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	log.Debug("Adding service", "isd_as", ia, "svc", svc, "ip", ip)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	return c.DataPlane.AddSvc(svc, &net.UDPAddr{IP: ip, Port: topology.EndhostPort})
}

// DelSvc deletes the service entry for the given ISD-AS and IP pair.
func (c *Connector) DelSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	log.Debug("Deleting service", "isd_as", ia, "svc", svc, "ip", ip)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	return c.DataPlane.DelSvc(svc, &net.UDPAddr{IP: ip, Port: topology.EndhostPort})
}

// SetKey sets the key for the given ISD-AS at the given index.
func (c *Connector) SetKey(ia addr.IA, index int, key []byte) error {
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
func (c *Connector) SetRevocation(ia addr.IA, ifID common.IFIDType, rev []byte) error {
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	log.Info("SetRevocation is not supported")
	return nil
}

// DelRevocation deletes the revocation for the given ISD-AS and interface.
func (c *Connector) DelRevocation(ia addr.IA, ifid common.IFIDType) error {
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	log.Info("DelRevocation is not supported")
	return nil
}
