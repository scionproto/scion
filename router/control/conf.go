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

// Package control is the configuration API of the router and specifies the management interface
// expected of the router.
package control

import (
	"crypto/sha256"
	"net/netip"
	"sort"

	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/private/topology"
)

// Dataplane is the interface that this controller or the http status handler expect from the
// Dataplane.
type Dataplane interface {
	CreateIACtx(ia addr.IA) error
	AddInternalInterface(ia addr.IA, local netip.AddrPort) error
	AddExternalInterface(
		localIfID iface.ID, info LinkInfo, localHost, remoteHost addr.Host, owned bool) error
	AddSvc(ia addr.IA, svc addr.SVC, a netip.AddrPort) error
	DelSvc(ia addr.IA, svc addr.SVC, a netip.AddrPort) error
	SetKey(ia addr.IA, index int, key []byte) error
	SetPortRange(start, end uint16)
}

// BFD is the configuration for the BFD sessions.
type BFD topology.BFD

// LinkInfo contains the information about a link between an internal and
// external router.
type LinkInfo struct {
	Provider string
	Local    LinkEnd
	Remote   LinkEnd
	Instance string
	LinkTo   topology.LinkType
	BFD      BFD
	MTU      int
}

// LinkEnd represents one end of a link.
type LinkEnd struct {
	IA   addr.IA
	Addr string
	IfID iface.ID
}

// AddrInfo describes an Address in a underlay-independent format.
type AddrInfo struct {
	underlay string // The underlay provider that can use the address
	address  string // String representation that the underlay can interpret.
}

type ObservableDataplane interface {
	ListInternalInterfaces() ([]InternalInterface, error)
	ListExternalInterfaces() ([]ExternalInterface, error)
	ListSiblingInterfaces() ([]SiblingInterface, error)
}

// InternalInterface represents the internal underlay interface of a router.
type InternalInterface struct {
	IA   addr.IA
	Addr netip.AddrPort // Still restricted to UDP/IP for now.
}

// ExternalInterface represents an external underlay interface of a router.
type ExternalInterface struct {
	// InterfaceID is the identifier of the external interface.
	IfID uint16
	// Link is the information associated with this link.
	Link LinkInfo
	// State indicates the interface state.
	State InterfaceState
}

// SiblingInterface represents a sibling underlay interface of a router. A sibling interface
// is an external interface owned by another router in the same AS.
type SiblingInterface struct {
	// InterfaceID is the identifier of the external interface.
	IfID uint16
	// InternalInterfaces is the local address (internal interface)
	// of the sibling router that owns this interface.
	InternalInterface string // Underlay agnostic address format
	// Relationship describes the type of inter-AS links.
	Relationship topology.LinkType
	// MTU is the maximum Transmission Unit for SCION packets.
	MTU int
	// NeighborIA is the ISD-AS number of the neighbor AS this interface connects to.
	NeighborIA addr.IA
	// State indicates the interface state. This refers to the connectivity state
	// of the internal network to reach this interface. It does not specify the
	// state of the interface itself.
	State InterfaceState
}

// InterfaceState indicates the state of the interface.
type InterfaceState string

const (
	InterfaceUp   InterfaceState = "up"
	InterfaceDown InterfaceState = "down"
)

// ConfigDataplane configures the data-plane with the new configuration.
func ConfigDataplane(dp Dataplane, cfg *Config) error {
	if cfg == nil {
		// No configuration, nothing to do
		return serrors.New("empty configuration")
	}
	// Set ISD-AS
	if err := dp.CreateIACtx(cfg.IA); err != nil {
		return err
	}
	// Set Keys
	// XXX HSR currently only support 1 key, so use Key0
	// Should it be an error if no key is set?
	if len(cfg.MasterKeys.Key0) > 0 {
		key0 := DeriveHFMacKey(cfg.MasterKeys.Key0)
		if err := dp.SetKey(cfg.IA, 0, key0); err != nil {
			return err
		}
	}

	// Add internal interfaces
	if cfg.BR != nil {
		if cfg.BR.InternalAddr != (netip.AddrPort{}) {
			// TODO: Investigate what legitimate reason there would be to not have an internal addr.
			// Currently the router would panic upon Run().
			if err := dp.AddInternalInterface(cfg.IA, cfg.BR.InternalAddr); err != nil {
				return err
			}
		}
		// Add external interfaces
		if err := confExternalInterfaces(dp, cfg); err != nil {
			return err
		}
	}
	// Set SVC services, a.k.a. SVC resolution
	if err := confServices(dp, cfg); err != nil {
		return err
	}
	// Set Endhost port range
	dp.SetPortRange(cfg.Topo.PortRange())
	return nil
}

// DeriveHFMacKey derives the MAC key from the given key.
func DeriveHFMacKey(k []byte) []byte {
	if len(k) == 0 {
		panic("empty key")
	}
	// XXX Generate keys - MUST be kept in sync with pkg/scrypto/mac.go
	hfMacSalt := []byte("Derive OF Key")
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	return pbkdf2.Key(k, hfMacSalt, 1000, 16, sha256.New)
}

func confExternalInterfaces(dp Dataplane, cfg *Config) error {
	// Sort out keys/ifIDs to get deterministic order for unit testing
	infoMap := cfg.Topo.IFInfoMap()
	if len(infoMap) == 0 {
		// nothing to do
		return nil
	}
	ifIDs := []iface.ID{}
	for k := range infoMap {
		ifIDs = append(ifIDs, k)
	}
	sort.Slice(ifIDs, func(i, j int) bool { return ifIDs[i] < ifIDs[j] })
	// External interfaces
	for _, ifID := range ifIDs {
		iface := infoMap[ifID]
		linkInfo := LinkInfo{
			Provider: iface.Provider,
			Local: LinkEnd{
				IA:   cfg.IA,
				Addr: iface.Local,
				IfID: iface.ID,
			},
			Remote: LinkEnd{
				IA:   iface.IA,
				Addr: iface.Remote,
				IfID: iface.RemoteIfID,
			},
			Instance: iface.BRName,
			BFD:      BFD(iface.BFD),
			LinkTo:   iface.LinkType,
			MTU:      iface.MTU,
		}

		// Host addresses are currently constructed from a hosts's internal underlay address
		// under the assumption that it is always a UDP/IP address. These might have nothing
		// to do with the local end of external or sibling links.
		// TODO(multi_underlay): for now, we have no way to know the remote host address, so
		// until the configuration schema catches up we have to assume that the remote address
		// of the link is a udpip address and that it makes an acceptable scion Host address, as
		// it has been so far. Routers do not need to resolve their own Host addresses but it
		// needs to be valid. May be we should have an "unspecified" address for such purposes.
		localHost := addr.HostIP(cfg.BR.InternalAddr.Addr())
		remoteAddr, err := netip.ParseAddrPort(linkInfo.Remote.Addr)
		if err != nil {
			return err
		}
		remoteHost := addr.HostIP(remoteAddr.Addr())

		_, owned := cfg.BR.IFs[ifID]
		if !owned {
			// When an interface is not "owned", it means that it's proximal end is at another
			// router in the same AS (the owning router a.k.a. the sibling router). From the
			// point-of-view of the local router, the traffic must go through an intermediate
			// link that connects the local router to its sibling. Until the config schema catches
			// up, we use internal interfaces for sibling links.
			linkInfo.Provider = "udpip" // For now, all internal interfaces use udp/ip.
			linkInfo.Local.Addr = cfg.BR.InternalAddr.String()
			linkInfo.Remote.Addr = iface.InternalAddr.String() // i.e. via sibling router.

			// The link is between two AS-local routers. TODO(multi_underlay): double check it's
			// not used for other purposes where the far router's AS is expected.
			// If not, we should add: linkInfo.Remote.IA = linkInfo.Local.IA

			// For internal BFD always use the default configuration.
			linkInfo.BFD = BFD{}
		}

		if err := dp.AddExternalInterface(ifID, linkInfo, localHost, remoteHost, owned); err != nil {
			return err
		}
	}
	return nil
}

var svcTypes = []addr.SVC{
	addr.SvcDS,
	addr.SvcCS,
}

func confServices(dp Dataplane, cfg *Config) error {
	if cfg.Topo == nil {
		// nothing to tdo
		return nil
	}
	for _, svc := range svcTypes {
		addrs, err := cfg.Topo.Multicast(svc)
		if err != nil {
			// XXX assumption is that any error means there are no addresses for the SVC type
			continue
		}
		// Sort to get deterministic unit test, shouldn't matter for SVC resolution
		sort.Slice(addrs, func(i, j int) bool {
			return addrs[i].IP.String() < addrs[j].IP.String()
		})
		for _, a := range addrs {
			if err := dp.AddSvc(cfg.IA, svc, a.AddrPort()); err != nil {
				return err
			}
		}
	}
	return nil
}
