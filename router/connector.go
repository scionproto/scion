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
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/private/env"
	"github.com/scionproto/scion/router/config"
	"github.com/scionproto/scion/router/control"
)

// Connector implements the Dataplane interface used by the router control API. It sets
// up connections for the data plane.
type Connector struct {
	DataPlane dataPlane

	ia                 addr.IA
	mtx                sync.Mutex
	internalInterfaces []control.InternalInterface
	externalInterfaces map[uint16]control.ExternalInterface
	siblingInterfaces  map[uint16]control.SiblingInterface
	ReceiveBufferSize  int
	SendBufferSize     int

	BFD                 config.BFD
	DispatchedPortStart *int
	DispatchedPortEnd   *int
}

var errMultiIA = serrors.New("different IA not allowed")

// NewConnector returns a new connector: a data plane decorated with
// a configuration interface.
func NewConnector(config config.RouterConfig, features env.Features) *Connector {
	return &Connector{
		DataPlane: makeDataPlane(
			RunConfig{
				NumProcessors:         config.NumProcessors,
				NumSlowPathProcessors: config.NumSlowPathProcessors,
				BatchSize:             config.BatchSize,
				ReceiveBufferSize:     config.ReceiveBufferSize,
				SendBufferSize:        config.SendBufferSize,
			},
			features.ExperimentalSCMPAuthentication,
		),
		ReceiveBufferSize:   config.ReceiveBufferSize,
		SendBufferSize:      config.SendBufferSize,
		BFD:                 config.BFD,
		DispatchedPortStart: config.DispatchedPortStart,
		DispatchedPortEnd:   config.DispatchedPortEnd,
	}
}

// CreateIACtx creates the context for ISD-AS.
func (c *Connector) CreateIACtx(ia addr.IA) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("CreateIACtx", "isd_as", ia)
	if !c.ia.IsZero() {
		return serrors.JoinNoStack(errMultiIA, nil, "current", c.ia, "new", ia)
	}
	c.ia = ia
	return c.DataPlane.SetIA(ia)
}

// AddInternalInterface adds the internal interface.
func (c *Connector) AddInternalInterface(
	ia addr.IA, localHost addr.Host, provider, localAddr string) error {

	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Adding internal interface", "isd_as", ia, "local", localAddr)
	if !c.ia.Equal(ia) {
		return serrors.JoinNoStack(errMultiIA, nil, "current", c.ia, "new", ia)
	}
	c.internalInterfaces = append(c.internalInterfaces, control.InternalInterface{
		IA:       ia,
		Provider: provider,
		Addr:     localAddr,
	})
	return c.DataPlane.AddInternalInterface(localHost, provider, localAddr)
}

// AddExternalInterface adds a link between the local and remote address.
func (c *Connector) AddExternalInterface(
	localIfID iface.ID, link control.LinkInfo, localHost, remoteHost addr.Host, owned bool) error {

	c.mtx.Lock()
	defer c.mtx.Unlock()
	intf := uint16(localIfID)
	log.Debug("Adding external interface", "interface", localIfID,
		"local_isd_as", link.Local.IA, "local_addr", link.Local.Addr,
		"remote_isd_as", link.Remote.IA, "remote_addr", link.Remote.Addr,
		"owned", owned,
		"link_bfd_configured", link.BFD.Disable != nil,
		"link_bfd_enabled", link.BFD.Disable == nil || !*link.BFD.Disable,
		"dataplane_bfd_enabled", !c.BFD.Disable)

	if !c.ia.Equal(link.Local.IA) {
		return serrors.JoinNoStack(errMultiIA, nil, "current", c.ia, "new", link.Local.IA)
	}
	if err := c.DataPlane.AddNeighborIA(intf, link.Remote.IA); err != nil {
		return serrors.Wrap("adding neighboring IA", err, "if_id", localIfID)
	}

	link.BFD = c.applyBFDDefaults(link.BFD)
	if !owned {
		if len(c.siblingInterfaces) == 0 {
			c.siblingInterfaces = make(map[uint16]control.SiblingInterface)
		}
		c.siblingInterfaces[intf] = control.SiblingInterface{
			IfID:            intf,
			InternalAddress: link.Remote.Addr, // address of the sibling router
			Relationship:    link.LinkTo,
			MTU:             link.MTU,
			NeighborIA:      link.Remote.IA,
			State:           control.InterfaceDown,
		}
		return c.DataPlane.AddNextHop(intf, link, localHost, remoteHost)
	}

	if len(c.externalInterfaces) == 0 {
		c.externalInterfaces = make(map[uint16]control.ExternalInterface)
	}
	c.externalInterfaces[intf] = control.ExternalInterface{
		IfID:  intf,
		Link:  link,
		State: control.InterfaceDown,
	}
	return c.DataPlane.AddExternalInterface(intf, link, localHost, remoteHost)
}

// AddSvc adds the service address for the given ISD-AS.
func (c *Connector) AddSvc(ia addr.IA, svc addr.SVC, a addr.Host, p uint16) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Adding service", "isd_as", ia, "svc", svc, "address", a, "port", p)
	if !c.ia.Equal(ia) {
		return serrors.JoinNoStack(errMultiIA, nil, "current", c.ia, "new", a)
	}
	return c.DataPlane.AddSvc(svc, a, p)
}

// DelSvc deletes the service entry for the given ISD-AS and IP pair.
func (c *Connector) DelSvc(ia addr.IA, svc addr.SVC, a addr.Host, p uint16) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Deleting service", "isd_as", ia, "svc", svc, "address", a)
	if !c.ia.Equal(ia) {
		return serrors.JoinNoStack(errMultiIA, nil, "current", c.ia, "new", a)
	}
	return c.DataPlane.DelSvc(svc, a, p)
}

// SetKey sets the key for the given ISD-AS at the given index.
func (c *Connector) SetKey(ia addr.IA, index int, key []byte) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Setting key", "isd_as", ia, "index", index)
	if !c.ia.Equal(ia) {
		return serrors.JoinNoStack(errMultiIA, nil, "current", c.ia, "new", ia)
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
		externalInterface.State = c.DataPlane.getInterfaceState(externalInterface.IfID)
		externalInterfaceList = append(externalInterfaceList, externalInterface)
	}
	return externalInterfaceList, nil
}

func (c *Connector) ListSiblingInterfaces() ([]control.SiblingInterface, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	siblingInterfaceList := make([]control.SiblingInterface, 0, len(c.siblingInterfaces))
	for _, siblingInterface := range c.siblingInterfaces {
		siblingInterface.State = c.DataPlane.getInterfaceState(siblingInterface.IfID)
		siblingInterfaceList = append(siblingInterfaceList, siblingInterface)
	}
	return siblingInterfaceList, nil
}

// applyBFDDefaults updates the given cfg object with the global default BFD settings.
// Link-specific settings, if configured, remain unchanged.  IMPORTANT: cfg.Disable isn't a boolean
// but a pointer to boolean, allowing a simple representation of the unconfigured state: nil. This
// means that using a cfg object that hasn't been processed by this function may lead to a NPE.
// In particular, "control.BFD{}" is invalid.
func (c *Connector) applyBFDDefaults(cfg control.BFD) control.BFD {

	if cfg.Disable == nil {
		disable := c.BFD.Disable
		cfg.Disable = &disable
	}
	if cfg.DetectMult == 0 {
		cfg.DetectMult = c.BFD.DetectMult
	}
	if cfg.DesiredMinTxInterval == 0 {
		cfg.DesiredMinTxInterval = c.BFD.DesiredMinTxInterval.Duration
	}
	if cfg.RequiredMinRxInterval == 0 {
		cfg.RequiredMinRxInterval = c.BFD.RequiredMinRxInterval.Duration
	}
	return cfg
}

func (c *Connector) SetPortRange(start, end uint16) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.DispatchedPortStart != nil {
		start = uint16(*c.DispatchedPortStart)
	}
	if c.DispatchedPortEnd != nil {
		end = uint16(*c.DispatchedPortEnd)
	}
	log.Debug("Endhost port range configuration", "startPort", start, "endPort", end)
	c.DataPlane.SetPortRange(start, end)
}
