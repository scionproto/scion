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

package multihomed_test

import (
	"crypto/rand"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/snet/multihomed"
)

func TestMultihomed(t *testing.T) {
	suite.Run(t, NewMultihomedTestSuite())
}

// MultihomedTestSuite ensures that each test in this package is run correctly, even
// in the presence of test functions that alter the internal behaviour of mutexes or
// critical data structures. This is done by protecting the execution of each test function
// with a RWMutex, allowing "regular" tests to obtain a read lock, and "special" tests
// to get a write lock, forcing them run in isolation.
// It allows to call t.Parallel() in any and all test functions.
type MultihomedTestSuite struct {
	suite.Suite
	muInternalsIsolated sync.RWMutex
}

func NewMultihomedTestSuite() *MultihomedTestSuite {
	return &MultihomedTestSuite{}
}

func (s *MultihomedTestSuite) SetupTest() {
	s.muInternalsIsolated.RLock()
}

func (s *MultihomedTestSuite) TearDownTest() {
	s.muInternalsIsolated.RUnlock()
}

func (s *MultihomedTestSuite) TestListInterfaces() {
	t := s.T()
	t.Parallel()
	addrs := multihomed.MustGetEgressIpAddresses(t)
	require.NotEmpty(t, addrs)
}

func (s *MultihomedTestSuite) TestInternalEgressCache() {
	t := s.T()
	// We require this function to run in isolation: lock every other test.
	s.muInternalsIsolated.RUnlock()
	s.muInternalsIsolated.Lock()
	defer func() {
		// Because we hold the write lock, unlock it.
		s.muInternalsIsolated.Unlock()
		// Because the test suite will expect a read lock, get it.
		s.muInternalsIsolated.RLock()
	}()

	// Synchronize with the internal ticker routine to ensure it finished the update.
	checkTicker := time.NewTicker(10 * time.Millisecond)
	for i, _ := 0, <-checkTicker.C; i < 10; i, _ = i+1, <-checkTicker.C {
		multihomed.GetInternalMutex().RLock()
		state := *multihomed.GetEgressesLastState()
		multihomed.GetInternalMutex().RUnlock()
		// Check that the egress table is not empty.
		if len(state) > 0 {
			break
		}
	}
	checkTicker.Stop()
	require.NotEmpty(t, *multihomed.GetEgressesLastState())

	// Stop internal refresh method.
	multihomed.StopTicker()

	// Clear map.
	multihomed.ReplaceRemoteToEgressMap(make(map[netip.Addr]netip.Addr))
	require.Empty(t, multihomed.GetRemoteToEgressMap())

	// Create a pretend remote endpoint.
	const mockRemoteAddress = "127.1.2.3"
	const mockEgressAddress = "127.1.2.100"
	mockRemote := xtest.MustParseUDPAddr(t, mockRemoteAddress+":22")

	// Add mock remote entry to map.
	multihomed.ReplaceRemoteToEgressMap(map[netip.Addr]netip.Addr{
		netip.MustParseAddr(mockRemoteAddress): netip.MustParseAddr(mockEgressAddress),
	})

	// Actual test, get the egress address for the remote.
	expected := xtest.MustParseIP(t, mockEgressAddress).To4()
	got, err := multihomed.OutboundIP(mockRemote)
	require.NoError(t, err)
	require.Equal(t, expected, got)
}

// BenchmarkSyncMapWrites (and the other 3 analogous benchmarks) are used to check the performance
// of a sync.Map (any->any) and a regular map (IP->IP) with a RWMutex.
func BenchmarkSyncMapWrites(b *testing.B) {
	// Create a set of `size` IP addresses.
	addrs := generateIpAddrs(b.N)

	m := sync.Map{}
	b.ResetTimer()
	storeInSyncMap(&m, addrs)
}

func BenchmarkSyncMapReads(b *testing.B) {
	addrs := generateIpAddrs(b.N)
	m := sync.Map{}
	storeInSyncMap(&m, addrs)

	// Refrain optimizer from removing code by adding the values to a discard buffer.
	discardBuff := make([]netip.Addr, b.N)
	b.ResetTimer()
	for i, addr := range addrs {
		a, ok := m.Load(addr)
		addr = a.(netip.Addr)
		_ = ok
		discardBuff[i] = addr
	}
	b.StopTimer()
	require.NotEmpty(b, discardBuff)
	require.Len(b, discardBuff, b.N)
}

func BenchmarkMuMapWrites(b *testing.B) {
	addrs := generateIpAddrs(b.N)

	m := make(map[netip.Addr]netip.Addr)
	mu := sync.RWMutex{}
	b.ResetTimer()
	storeInMuMap(m, &mu, addrs)
}

func BenchmarkMuMapReads(b *testing.B) {
	addrs := generateIpAddrs(b.N)
	m := make(map[netip.Addr]netip.Addr)
	mu := sync.RWMutex{}
	storeInMuMap(m, &mu, addrs)

	// Refrain optimizer from removing code by adding the values to a discard buffer.
	discardBuff := make([]netip.Addr, b.N)
	b.ResetTimer()
	for i, addr := range addrs {
		mu.RLock()
		addr, ok := m[addr]
		mu.RUnlock()
		_ = ok
		discardBuff[i] = addr
	}
	b.StopTimer()
	require.NotEmpty(b, discardBuff)
	require.Len(b, discardBuff, b.N)
}

func generateIpAddrs(size int) []netip.Addr {
	addrs := make([]netip.Addr, size)
	raw := [4]byte{}
	for i := range size {
		rand.Read(raw[:])
		addrs[i] = netip.AddrFrom4(raw)
	}
	return addrs
}

func storeInSyncMap(m *sync.Map, addrs []netip.Addr) {
	for _, addr := range addrs {
		m.Store(addr, addr)
	}
}

func storeInMuMap(m map[netip.Addr]netip.Addr, mu *sync.RWMutex, addrs []netip.Addr) {
	for _, addr := range addrs {
		mu.Lock()
		m[addr] = addr
		mu.Unlock()
	}
}
