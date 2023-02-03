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

package routing

import (
	"net"
	"net/netip"

	"go4.org/netipx"

	"github.com/scionproto/scion/pkg/addr"
)

// AdvertiseList returns the list of prefixes to advertise for the given policy
// and ISD-ASes.
func AdvertiseList(pol *Policy, from, to addr.IA) ([]netip.Prefix, error) {
	if pol == nil {
		return []netip.Prefix{}, nil
	}
	var nets []netip.Prefix
	for _, r := range pol.Rules {
		if r.Action != Advertise || !r.From.Match(from) || !r.To.Match(to) {
			continue
		}
		if r.Network.Negated {
			continue
		}
		nets = append(nets, r.Network.Allowed...)
	}
	return nets, nil
}

// StaticAdvertised returns the list of all prefixes that can be advertised.
// Used for reporting purposes.
func StaticAdvertised(pol *Policy) []*net.IPNet {
	if pol == nil {
		return []*net.IPNet{}
	}
	var nets []*net.IPNet
	for _, r := range pol.Rules {
		if r.Action != Advertise {
			continue
		}
		if r.Network.Negated {
			continue
		}
		for _, prefix := range r.Network.Allowed {
			nets = append(nets, netipx.PrefixIPNet(prefix))
		}
	}
	return nets
}
