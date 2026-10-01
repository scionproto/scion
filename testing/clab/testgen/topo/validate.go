// Copyright 2026 Anapaya Systems
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

package topo

import (
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
)

// Validate performs referential and consistency checks on the topology.
func (t *Topo) Validate() error {
	if len(t.ASes) == 0 {
		return serrors.New("topology has no ASes")
	}

	// cert_issuer references must point at an issuing AS.
	for ia, e := range t.ASes {
		if e.MTU != 0 && e.MTU < MinMTU {
			return serrors.New("AS MTU below minimum", "as", ia, "mtu", e.MTU, "min", MinMTU)
		}
		if e.CertIssuer.IsZero() {
			continue
		}
		issuer, ok := t.ASes[e.CertIssuer]
		if !ok {
			return serrors.New("cert_issuer references unknown AS",
				"as", ia,
				"issuer", e.CertIssuer,
			)
		}
		if !issuer.Issuing {
			return serrors.New("cert_issuer is not an issuing AS", "as", ia, "issuer", e.CertIssuer)
		}
	}

	// Every ISD needs at least one core, voting, authoritative and issuing AS.
	type isdFlags struct{ core, voting, auth, issuing bool }
	isds := map[addr.ISD]*isdFlags{}
	for ia, e := range t.ASes {
		f := isds[ia.ISD()]
		if f == nil {
			f = &isdFlags{}
			isds[ia.ISD()] = f
		}
		f.core = f.core || e.Core
		f.voting = f.voting || e.Voting
		f.auth = f.auth || e.Authoritative
		f.issuing = f.issuing || e.Issuing
	}
	for isd, f := range isds {
		switch {
		case !f.core:
			return serrors.New("ISD has no core AS", "isd", isd)
		case !f.voting:
			return serrors.New("ISD has no voting AS", "isd", isd)
		case !f.auth:
			return serrors.New("ISD has no authoritative AS", "isd", isd)
		case !f.issuing:
			return serrors.New("ISD has no issuing AS", "isd", isd)
		}
	}

	// Links must reference known ASes and use unique interface ids per AS.
	used := map[addr.IA]map[iface.ID]struct{}{}
	markIfID := func(e Endpoint) error {
		if _, ok := t.ASes[e.IA]; !ok {
			return serrors.New("link references unknown AS", "as", e.IA)
		}
		m := used[e.IA]
		if m == nil {
			m = map[iface.ID]struct{}{}
			used[e.IA] = m
		}
		if _, dup := m[e.IfID]; dup {
			return serrors.New("duplicate interface id", "as", e.IA, "ifid", e.IfID)
		}
		m[e.IfID] = struct{}{}
		return nil
	}
	for i, l := range t.Links {
		if l.LinkAtoB == "" {
			return serrors.New("link missing linkAtoB", "index", i)
		}
		if l.MTU != 0 && l.MTU < MinMTU {
			return serrors.New("link MTU below minimum", "index", i, "mtu", l.MTU, "min", MinMTU)
		}
		if err := markIfID(l.A); err != nil {
			return serrors.Wrap("validating link endpoint A", err, "index", i)
		}
		if err := markIfID(l.B); err != nil {
			return serrors.Wrap("validating link endpoint B", err, "index", i)
		}
	}
	return nil
}
