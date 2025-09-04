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
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func MustGetEgressIpAddresses(t *testing.T) []netip.Addr {
	addrs, err := egressIpAddresses()
	require.NoError(t, err)
	return addrs
}

func GetInternalMutex() *sync.RWMutex {
	return &muRemoteToEgress
}

func StopTicker() {
	stopContinuousCheckInterfaces()
}

func GetRemoteToEgressMap() map[netip.Addr]netip.Addr {
	return remoteToEgress
}

func ReplaceRemoteToEgressMap(newMap map[netip.Addr]netip.Addr) {
	remoteToEgress = newMap
}

func GetEgressesLastState() *[]netip.Addr {
	return localAddresses.Load()
}
