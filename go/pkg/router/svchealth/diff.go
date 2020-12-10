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

package svchealth

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
)

// Diff keeps track of the differences between two topologies.
type Diff struct {
	Add    map[addr.HostSVC][]net.IP
	Remove map[addr.HostSVC][]net.IP
}

// ComputeDiff computes the difference between two topologies. Currently, only
// differences in the control service and SIG service IP addresses are
// considered.
func ComputeDiff(prev, next map[addr.HostSVC][]*net.UDPAddr) Diff {
	diff := Diff{
		Add:    map[addr.HostSVC][]net.IP{},
		Remove: map[addr.HostSVC][]net.IP{},
	}
	svcs := map[addr.HostSVC]struct{}{}
	for svc := range prev {
		svcs[svc] = struct{}{}
	}
	for svc := range next {
		svcs[svc] = struct{}{}
	}
	for svc := range svcs {
		if added := subtract(next[svc], prev[svc]); len(added) > 0 {
			diff.Add[svc] = added
		}
		if removed := subtract(prev[svc], next[svc]); len(removed) > 0 {
			diff.Remove[svc] = removed
		}
	}
	return diff
}

// subtract subtracts all the IPs in b from the ones in a.
func subtract(a, b []*net.UDPAddr) []net.IP {
	set := map[string]struct{}{}
	for _, addr := range a {
		set[string(addr.IP)] = struct{}{}
	}
	for _, addr := range b {
		delete(set, string(addr.IP))
	}
	ips := make([]net.IP, 0, len(set))
	for ip := range set {
		ips = append(ips, net.IP(ip))
	}
	return ips
}
