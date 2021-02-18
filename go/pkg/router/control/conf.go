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

package control

import (
	"crypto/sha256"
	"net"
	"sort"

	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
)

// Dataplane is the interface that a dataplane has to support to be controlled
// by this controller.
type Dataplane interface {
	CreateIACtx(ia addr.IA) error
	AddInternalInterface(ia addr.IA, local net.UDPAddr) error
	AddExternalInterface(localIfID common.IFIDType, info LinkInfo, owned bool) error
	AddSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error
	DelSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error
	SetKey(ia addr.IA, index int, key []byte) error

	SetRevocation(ia addr.IA, ifid common.IFIDType, rev []byte) error
	DelRevocation(ia addr.IA, ifid common.IFIDType) error
}

// LinkInfo contains the information about a link between an internal and
// external router.
type LinkInfo struct {
	Local    LinkEnd
	Remote   LinkEnd
	Instance string
	LinkTo   topology.LinkType
	BFD      BFD
	MTU      int
}

// LinkEnd represents on end of a link.
type LinkEnd struct {
	IA   addr.IA
	Addr *net.UDPAddr
}

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
		if cfg.BR.InternalAddr != nil {
			if err := dp.AddInternalInterface(cfg.IA, *cfg.BR.InternalAddr); err != nil {
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
	return nil
}

// DeriveHFMacKey derives the MAC key from the given key.
func DeriveHFMacKey(k []byte) []byte {
	if len(k) == 0 {
		panic("empty key")
	}
	// XXX Generate keys - MUST be kept in sync with go/lib/scrypto/mac.go
	hfMacSalt := []byte("Derive OF Key")
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	return pbkdf2.Key(k, hfMacSalt, 1000, 16, sha256.New)
}

func confExternalInterfaces(dp Dataplane, cfg *Config) error {
	// Sort out keys/ifids to get deterministic order for unit testing
	infoMap := cfg.Topo.IFInfoMap()
	if len(infoMap) == 0 {
		// nothing to do
		return nil
	}
	ifids := []common.IFIDType{}
	for k := range infoMap {
		ifids = append(ifids, k)
	}
	sort.Slice(ifids, func(i, j int) bool { return ifids[i] < ifids[j] })
	// External interfaces
	for _, ifid := range ifids {
		iface := infoMap[ifid]
		linkInfo := LinkInfo{
			Local: LinkEnd{
				IA:   cfg.IA,
				Addr: snet.CopyUDPAddr(iface.Local),
			},
			Remote: LinkEnd{
				IA:   iface.IA,
				Addr: snet.CopyUDPAddr(iface.Remote),
			},
			Instance: iface.BRName,
			BFD:      withDefaults(BFD(iface.BFD)),
			LinkTo:   iface.LinkType,
			MTU:      iface.MTU,
		}

		_, owned := cfg.BR.IFs[ifid]
		if !owned {
			// XXX The current implementation effectively uses IP/UDP tunnels to create
			// the SCION network as an overlay, with forwarding to local hosts being a special case.
			// When setting up external interfaces that belong to other routers in the AS, they
			// are basically IP/UDP tunnels between the two border routers, and as such is
			// configured in the data plane.
			linkInfo.Local.Addr = snet.CopyUDPAddr(cfg.BR.InternalAddr)
			linkInfo.Remote.Addr = snet.CopyUDPAddr(iface.InternalAddr)
			// For internal BFD always use the default configuration, which can be modified with
			// the env variables.
			linkInfo.BFD = bfdDefaults
		}

		if err := dp.AddExternalInterface(ifid, linkInfo, owned); err != nil {
			return err
		}
	}
	return nil
}

var svcTypes = []addr.HostSVC{
	addr.SvcDS,
	addr.SvcCS,
	addr.SvcSB,
	addr.SvcSIG,
	addr.SvcHPS,
}

func confServices(dp Dataplane, cfg *Config) error {
	if cfg.Topo == nil {
		// nothing to tdo
		return nil
	}
	for _, svc := range svcTypes {
		addrs, err := cfg.Topo.UnderlayMulticast(svc)
		if err != nil {
			// XXX assumption is that any error means there are no addresses for the SVC type
			continue
		}
		// Sort to get deterministic unit test, shouldn't matter for SVC resolution
		sort.Slice(addrs, func(i, j int) bool {
			return addrs[i].IP.String() < addrs[j].IP.String()
		})
		for _, a := range addrs {
			if err := dp.AddSvc(cfg.IA, svc, a.IP); err != nil {
				return err
			}
		}
	}
	return nil
}
