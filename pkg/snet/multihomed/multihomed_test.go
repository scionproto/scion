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
type MultihomedTestSuite struct {
	suite.Suite
	muInternalsIsolated sync.RWMutex
}

func NewMultihomedTestSuite() *MultihomedTestSuite {
	return &MultihomedTestSuite{
		muInternalsIsolated: sync.RWMutex{},
	}
}

func (s *MultihomedTestSuite) SetupTest() {
	s.T().Log("--> setting up test")
	s.muInternalsIsolated.RLock()
}

func (s *MultihomedTestSuite) TearDownTest() {
	s.T().Log("<-- tearing down test")
	s.muInternalsIsolated.RUnlock()
}

func (s *MultihomedTestSuite) TestListInterfaces() {
	t := s.T()
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

	// Wait for 100ms allow the ticker to run first.
	time.Sleep(100 * time.Millisecond)

	// Synchronize with the internal ticker routine to ensure it finished the update.
	multihomed.GetInternalMutex().RLock()
	// Check that the egress table is not empty.
	require.NotEmpty(t, *multihomed.GetEgressesLastState())
	multihomed.GetInternalMutex().RUnlock()

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
