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

	"github.com/scionproto/scion/go/lib/addr"
)

// AdvertiseList returns the list of prefixes to advertise for the given policy
// and ISD-ASes.
func AdvertiseList(pol *Policy, from, to addr.IA) []*net.IPNet {
	return extractList(pol, from, to, Advertise)
}

// AllowedPrefixesBGP returns the list of prefixes that are allowed to be
// redistributed from BGP.
func AllowedPrefixesBGP(pol *Policy, from, to addr.IA) []*net.IPNet {
	return extractList(pol, from, to, RedistributeBGP)
}

func extractList(pol *Policy, from, to addr.IA, action Action) []*net.IPNet {
	if pol == nil {
		return []*net.IPNet{}
	}
	var nets []*net.IPNet
	for _, r := range pol.Rules {
		if r.Action != action || !r.From.Match(from) || !r.To.Match(to) {
			continue
		}
		m, ok := r.Network.(allowedNetworkMatcher)
		if !ok {
			continue
		}
		nets = append(nets, m.Allowed...)
	}
	return nets
}

// StaticAdvertised returns the list of all prefixes that are advertised.
func StaticAdvertised(pol *Policy) []*net.IPNet {
	if pol == nil {
		return []*net.IPNet{}
	}
	var nets []*net.IPNet
	for _, r := range pol.Rules {
		if r.Action != Advertise {
			continue
		}
		m, ok := r.Network.(allowedNetworkMatcher)
		if !ok {
			continue
		}
		nets = append(nets, m.Allowed...)
	}
	return nets
}
