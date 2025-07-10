// Copyright 2025 Anapaya Systems
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

package discovery

import (
	"errors"
	"net/netip"

	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/slices"
)

// Extension is the discovery extension for SCION segments.
type Extension struct {
	ControlServices   []netip.AddrPort
	DiscoveryServices []netip.AddrPort
}

func FromPB(pb *cppb.DiscoveryExtension) (*Extension, error) {
	if pb == nil {
		return nil, nil
	}
	var cses, dses []netip.AddrPort
	var parseErrors []error
	for _, a := range pb.ControlServiceAddresses {
		cs, err := netip.ParseAddrPort(a)
		if err == nil {
			cses = append(cses, cs)
			continue
		}
		parseErrors = append(parseErrors, err)
	}
	for _, a := range pb.DiscoveryServiceAddresses {
		ds, err := netip.ParseAddrPort(a)
		if err == nil {
			dses = append(dses, ds)
			continue
		}
		parseErrors = append(parseErrors, err)
	}
	if (len(pb.ControlServiceAddresses) > 0 && len(cses) == 0) ||
		(len(pb.DiscoveryServiceAddresses) > 0 && len(dses) == 0) {
		// If there are addresses in the pb, but none could be parsed
		// successfully, we return all parsing errors.
		return nil, errors.Join(parseErrors...)
	}
	return &Extension{
		ControlServices:   cses,
		DiscoveryServices: dses,
	}, nil
}

func ToPB(ext *Extension) *cppb.DiscoveryExtension {
	if ext == nil {
		return nil
	}
	return &cppb.DiscoveryExtension{
		ControlServiceAddresses:   slices.Transform(ext.ControlServices, netip.AddrPort.String),
		DiscoveryServiceAddresses: slices.Transform(ext.DiscoveryServices, netip.AddrPort.String),
	}
}
