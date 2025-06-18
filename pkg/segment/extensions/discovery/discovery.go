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
	cses, csErr := transformSliceWithError(
		pb.ControlServiceAddresses, netip.ParseAddrPort,
	)
	dses, dsErr := transformSliceWithError(
		pb.DiscoveryServiceAddresses, netip.ParseAddrPort,
	)
	if err := errors.Join(csErr, dsErr); err != nil {
		// If any of the addresses are invalid, we return nil.
		return nil, err
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

func transformSliceWithError[In any, Out any](
	in []In, transform func(In) (Out, error),
) ([]Out, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]Out, 0, len(in))
	for _, v := range in {
		if o, err := transform(v); err == nil {
			out = append(out, o)
		} else {
			return nil, err
		}
	}
	return out, nil
}
