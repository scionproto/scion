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

// The reasons to keep track of the current local addresses are that these two things can happen:
//  1. The interface is brought down and can't be used anymore. This requires the new
//     packet to be sent using a different interface, if any is available.
//  2. The interface changed address, which needs us to update the tables and record the
//     new address in use.
// The second event deals with the address only, without touching the routing table, while the
// first one modifies the routing table. For our purposes, both events modify the local address
// of the interface, and for both events the solution is to query the kernel again.
// This is why on the event of any address change, we completely clear the table, forcing
// the caller to perform a syscall to find the appropriate route.

// XXX(juagargi): The right way to keep this routing information updated is to use netlink.
// We however just keep a cache of the last used remote addresses mapped to our interfaces'
// local addresses. Additionally, if the current interfaces' local addresses change, we
// completely clear the cache.

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
)

const (
	CheckInterfacesPeriod = time.Second
	MaxAllowedCacheSize   = 65536 // Maximum number of entries present in `remoteToEgress`.
)

var (
	remoteToEgress   map[netip.Addr]netip.Addr = make(map[netip.Addr]netip.Addr)
	muRemoteToEgress sync.RWMutex              = sync.RWMutex{}

	// The local addresses are stored in an atomic pointer to allow tests to inspect the
	// internal value of it without data races.
	localAddresses = atomic.Pointer[[]netip.Addr]{}
	ticker         = time.NewTicker(CheckInterfacesPeriod)
	stopTicker     = make(chan struct{})
)

func init() {
	localAddrs := make([]netip.Addr, 0)
	localAddresses.Store(&localAddrs)
	go func() {
		defer log.HandlePanic()
		continuousCheckInterfaces()
	}()
}

// StopContinuousCheckInterfaces is used in tests where they need to stop the running
// goroutine that checks the state of the local interfaces.
func StopContinuousCheckInterfaces(*testing.T) {
	if testing.Testing() {
		stopContinuousCheckInterfaces()
	}
}

func continuousCheckInterfaces() {
	clearCacheIfLocalChanges()
loop:
	for {
		select {
		case <-ticker.C:
			clearCacheIfLocalChanges()
		case <-stopTicker:
			ticker.Stop()
			break loop
		}
	}
}

func clearCacheIfLocalChanges() {
	addrs := getInterfacesLocalAddresses()
	if addrs == nil {
		// Internal error, bail.
		return
	}

	// Compare with previous result.
	if equalAddressList(addrs, *localAddresses.Load()) {
		// They are the same, bail.
		return
	}

	// Not equal, invalidate every entry.
	invalidateAll()
	// And store previous state.
	localAddresses.Store(&addrs)
}

func getInterfacesLocalAddresses() []netip.Addr {
	// We only look at the local addresses. If they are not identical to the last call,
	// remove all entries from the map, forcing the callers to obtain a new routed egress.
	addrs, err := egressIpAddresses()
	if err != nil {
		// What do we do in this case?
		// We should at least log the error and erase all entries in the table.
		fmt.Fprintf(os.Stderr, "cannot list the network interfaces and their addresses: %s", err)
		invalidateAll()
		return nil
	}
	// Sort the result.
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].Compare(addrs[j]) < 0
	})
	return addrs
}

func equalAddressList(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Compare(b[i]) != 0 {
			return false
		}
	}
	return true
}

func invalidateAll() {
	muRemoteToEgress.Lock()
	remoteToEgress = make(map[netip.Addr]netip.Addr)
	muRemoteToEgress.Unlock()
}

func egressIpAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, serrors.Wrap("listing interfaces", err)
	}
	ipAddrs := make([]netip.Addr, 0, len(interfaces))

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, serrors.Wrap("getting interface addresses", err, "interface", iface.Name)
		}
		for _, addr := range addrs {
			ipAddr, ok := addr.(*net.IPNet)
			if ok {
				a, _ := netip.AddrFromSlice(ipAddr.IP)
				ipAddrs = append(ipAddrs, a)
			}
		}
	}

	return ipAddrs, nil
}

func stopContinuousCheckInterfaces() {
	stopTicker <- struct{}{}
}
