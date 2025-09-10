// Copyright 2025 ETH Zurich
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

package multihomed

import (
	"net"
	"net/netip"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// OutboundIP returns the IP address used by this host to dial to the specified remote host.
// The port value in the remote udp address is irrelevant.
// It relies on a previously populated table that maps remote addresses to egress addresses.
// If the remote is not present, it is added.
func OutboundIP(nextHop *net.UDPAddr) (net.IP, error) {
	remote, ok := netip.AddrFromSlice(nextHop.IP)
	if !ok {
		return nil, serrors.New("invalid IP address", "address", nextHop.IP)
	}

	// Check if the table contains an entry.
	muRemoteToEgress.RLock()
	egress, ok := remoteToEgress[remote]
	muRemoteToEgress.RLocker().Unlock()
	if ok {
		return net.IP(egress.AsSlice()), nil
	}

	// Not found, find it and add it. The dialing involves a syscall, but no network traffic.
	eg, err := dialRemote(nextHop)
	if err != nil {
		return nil, err
	}
	egress, _ = netip.AddrFromSlice(eg)

	muRemoteToEgress.Lock()
	// Check if our cache is not too big already.
	if len(remoteToEgress) < MaxAllowedCacheSize {
		remoteToEgress[remote] = egress
	}
	muRemoteToEgress.Unlock()

	return eg, nil
}

// dialRemote creates a socket used to send UDP packets to the remote endpoint.
// Note that while a syscall is performed (two including Close), there will be no network traffic.
// Anyhow, this is somewhat expensive, so try to reduce its usage.
func dialRemote(raddr *net.UDPAddr) (net.IP, error) {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// The conn object is always a net.UDPConn, with LocalAddr statically returning
	// always a *net.UDPAddr.
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}
