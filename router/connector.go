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
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router/control"
)

// Connector implements the Dataplane API of the router control process. It sets
// up connections for the DataPlane.
type Connector struct {
	DataPlane DataPlane

	ia                 addr.IA
	mtx                sync.Mutex
	internalInterfaces []control.InternalInterface
	externalInterfaces map[uint16]control.ExternalInterface
	siblingInterfaces  map[uint16]control.SiblingInterface

	ReceiveBufferSize int
	SendBufferSize    int
}

var errMultiIA = serrors.New("different IA not allowed")

// CreateIACtx creates the context for ISD-AS.
func (c *Connector) CreateIACtx(ia addr.IA) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("CreateIACtx", "isd_as", ia)
	if !c.ia.IsZero() {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	c.ia = ia
	return c.DataPlane.SetIA(ia)
}

// AddInternalInterface adds the internal interface.
func (c *Connector) AddInternalInterface(ia addr.IA, local net.UDPAddr) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Adding internal interface", "isd_as", ia, "local", local)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	connection, err := conn.New(&local, nil,
		&conn.Config{ReceiveBufferSize: c.ReceiveBufferSize, SendBufferSize: c.SendBufferSize})
	if err != nil {
		return err
	}
	c.internalInterfaces = append(c.internalInterfaces, control.InternalInterface{
		IA:   ia,
		Addr: &local,
	})
	return c.DataPlane.AddInternalInterface(connection, local.IP)
}

// AddExternalInterface adds a link between the local and remote address.
func (c *Connector) AddExternalInterface(localIfID common.IFIDType, link control.LinkInfo,
	owned bool) error {

	c.mtx.Lock()
	defer c.mtx.Unlock()
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

	if owned {
		if len(c.externalInterfaces) == 0 {
			c.externalInterfaces = make(map[uint16]control.ExternalInterface)
		}
		c.externalInterfaces[intf] = control.ExternalInterface{
			InterfaceID: intf,
			Link:        link,
			State:       control.InterfaceDown,
		}
	} else {
		if len(c.siblingInterfaces) == 0 {
			c.siblingInterfaces = make(map[uint16]control.SiblingInterface)
		}
		c.siblingInterfaces[intf] = control.SiblingInterface{
			InterfaceID:       intf,
			InternalInterface: link.Remote.Addr,
			Relationship:      link.LinkTo,
			MTU:               link.MTU,
			NeighborIA:        link.Remote.IA,
			State:             control.InterfaceDown,
		}
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
		&conn.Config{ReceiveBufferSize: c.ReceiveBufferSize, SendBufferSize: c.SendBufferSize})
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
func (c *Connector) AddSvc(ia addr.IA, svc addr.SVC, a *net.UDPAddr) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Adding service", "isd_as", ia, "svc", svc, "address", a)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	return c.DataPlane.AddSvc(svc, a)
}

// DelSvc deletes the service entry for the given ISD-AS and IP pair.
func (c *Connector) DelSvc(ia addr.IA, svc addr.SVC, a *net.UDPAddr) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Deleting service", "isd_as", ia, "svc", svc, "address", a)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	return c.DataPlane.DelSvc(svc, a)
}

// SetKey sets the key for the given ISD-AS at the given index.
func (c *Connector) SetKey(ia addr.IA, index int, key []byte) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Setting key", "isd_as", ia, "index", index)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	if index != 0 {
		return serrors.New("currently only index 0 key is supported")
	}
	return c.DataPlane.SetKey(key)
}

func (c *Connector) ListInternalInterfaces() ([]control.InternalInterface, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if len(c.internalInterfaces) == 0 {
		return nil, serrors.New("internal interface is not set")
	}
	return c.internalInterfaces, nil
}

func (c *Connector) ListExternalInterfaces() ([]control.ExternalInterface, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	externalInterfaceList := make([]control.ExternalInterface, 0, len(c.externalInterfaces))
	for _, externalInterface := range c.externalInterfaces {
		externalInterface.State = c.DataPlane.getInterfaceState(externalInterface.InterfaceID)
		externalInterfaceList = append(externalInterfaceList, externalInterface)
	}
	return externalInterfaceList, nil
}

func (c *Connector) ListSiblingInterfaces() ([]control.SiblingInterface, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	siblingInterfaceList := make([]control.SiblingInterface, 0, len(c.siblingInterfaces))
	for _, siblingInterface := range c.siblingInterfaces {
		siblingInterface.State = c.DataPlane.getInterfaceState(siblingInterface.InterfaceID)
		siblingInterfaceList = append(siblingInterfaceList, siblingInterface)
	}
	return siblingInterfaceList, nil
}
