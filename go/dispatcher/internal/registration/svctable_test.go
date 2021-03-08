// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package registration

import (
	"fmt"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
)

func TestSVCTableLookup(t *testing.T) {
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	value := "test value"

	testCases := map[string]struct {
		Svc      addr.HostSVC
		IP       net.IP
		Prepare  func(t *testing.T, table SVCTable)
		Expected []interface{}
	}{
		// Empty table test cases:
		"Anycast to nil address, not found": {
			Svc:     addr.SvcCS,
			Prepare: func(*testing.T, SVCTable) {},
		},
		"Anycast to some IPv4 address, not found": {
			Svc:     addr.SvcCS,
			IP:      net.IP{10, 2, 3, 4},
			Prepare: func(*testing.T, SVCTable) {},
		},
		"Multicast to some IPv4 address, not found": {
			Svc:     addr.SvcCS.Multicast(),
			Prepare: func(*testing.T, SVCTable) {},
		},

		// Table with 1 entry test cases:
		"anycasting to nil finds the entry": {
			Svc: addr.SvcCS,
			Prepare: func(t *testing.T, table SVCTable) {
				_, err := table.Register(addr.SvcCS, address, value)
				require.NoError(t, err)
			},
			Expected: []interface{}{value},
		},
		"multicasting to nil finds the entry": {
			Svc: addr.SvcCS.Multicast(),
			Prepare: func(t *testing.T, table SVCTable) {
				_, err := table.Register(addr.SvcCS, address, value)
				require.NoError(t, err)
			},
			Expected: []interface{}{value},
		},
		"anycasting to a different IP does not find the entry": {
			Svc: addr.SvcCS,
			IP:  net.IP{10, 5, 6, 7},
			Prepare: func(t *testing.T, table SVCTable) {
				_, err := table.Register(addr.SvcCS, address, value)
				require.NoError(t, err)
			},
		},
		"anycasting to a different SVC does not find the entry": {
			Svc: addr.SvcDS,
			IP:  address.IP,
			Prepare: func(t *testing.T, table SVCTable) {
				_, err := table.Register(addr.SvcCS, address, value)
				require.NoError(t, err)
			},
		},
		"anycasting to the same SVC and IP finds the entry": {
			Svc: addr.SvcCS,
			IP:  address.IP,
			Prepare: func(t *testing.T, table SVCTable) {
				_, err := table.Register(addr.SvcCS, address, value)
				require.NoError(t, err)
			},
			Expected: []interface{}{value},
		},
		"multicasting to the same SVC and IP finds the entry": {
			Svc: addr.SvcCS.Multicast(),
			Prepare: func(t *testing.T, table SVCTable) {
				_, err := table.Register(addr.SvcCS, address, value)
				require.NoError(t, err)
			},
			Expected: []interface{}{value},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			table := NewSVCTable()
			tc.Prepare(t, table)

			retValues := table.Lookup(tc.Svc, tc.IP)
			assert.Equal(t, tc.Expected, retValues)
		})
	}
}

func TestSVCTableRegistration(t *testing.T) {
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	value := "test value"

	testCases := map[string]struct {
		Prepare func(t *testing.T, table SVCTable)
		// Input Register
		Svc   addr.HostSVC
		Addr  *net.UDPAddr
		Value interface{}
		// Assertions
		ReferenceAssertion assert.ValueAssertionFunc
		ErrAssertion       assert.ErrorAssertionFunc
	}{
		// Empty table test cases:
		"Registering nil address fails": {
			Prepare:            func(*testing.T, SVCTable) {},
			Svc:                addr.SvcCS,
			Value:              value,
			ReferenceAssertion: assert.Nil,
			ErrAssertion:       assert.Error,
		},
		"Registering IPv4 zero address fails": {
			Prepare:            func(*testing.T, SVCTable) {},
			Svc:                addr.SvcCS,
			Addr:               &net.UDPAddr{IP: net.IPv4zero, Port: address.Port},
			Value:              value,
			ReferenceAssertion: assert.Nil,
			ErrAssertion:       assert.Error,
		},
		"Registering IPv6 zero address fail": {
			Prepare:            func(*testing.T, SVCTable) {},
			Svc:                addr.SvcCS,
			Addr:               &net.UDPAddr{IP: net.IPv6zero, Port: address.Port},
			Value:              value,
			ReferenceAssertion: assert.Nil,
			ErrAssertion:       assert.Error,
		},
		"Registering port zero fails": {
			Prepare:            func(*testing.T, SVCTable) {},
			Svc:                addr.SvcCS,
			Addr:               &net.UDPAddr{IP: address.IP},
			Value:              value,
			ReferenceAssertion: assert.Nil,
			ErrAssertion:       assert.Error,
		},
		"Registering SvcNone fails": {
			Prepare:            func(*testing.T, SVCTable) {},
			Svc:                addr.SvcNone,
			Addr:               address,
			Value:              value,
			ReferenceAssertion: assert.Nil,
			ErrAssertion:       assert.Error,
		},
		"Adding an address succeeds": {
			Prepare:            func(*testing.T, SVCTable) {},
			Svc:                addr.SvcCS,
			Addr:               address,
			Value:              value,
			ReferenceAssertion: assert.NotNil,
			ErrAssertion:       assert.NoError,
		},

		// Table with 1 entry test cases:
		"Registering the same address and different port succeeds": {
			Prepare: func(t *testing.T, table SVCTable) {
				_, err := table.Register(addr.SvcCS, address, value)
				require.NoError(t, err)
			},
			Svc: addr.SvcCS,
			Addr: &net.UDPAddr{
				IP:   address.IP,
				Port: address.Port + 1,
			},
			Value:              value,
			ReferenceAssertion: assert.NotNil,
			ErrAssertion:       assert.NoError,
		},
		"Registering the same address and same port fails": {
			Prepare: func(t *testing.T, table SVCTable) {
				_, err := table.Register(addr.SvcCS, address, value)
				require.NoError(t, err)
			},
			Svc:                addr.SvcCS,
			Addr:               address,
			Value:              value,
			ReferenceAssertion: assert.Nil,
			ErrAssertion:       assert.Error,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			table := NewSVCTable()
			tc.Prepare(t, table)

			reference, err := table.Register(tc.Svc, tc.Addr, value)
			tc.ErrAssertion(t, err)
			tc.ReferenceAssertion(t, reference)
		})
	}
}

func TestSVCTableOneItemAnycast(t *testing.T) {
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	diffIpSamePortAddress := &net.UDPAddr{IP: net.IP{10, 5, 6, 7}, Port: address.Port}
	value := "test value"
	otherValue := "other test value"

	prepare := func(t *testing.T) (SVCTable, Reference) {
		table := NewSVCTable()
		reference, err := table.Register(addr.SvcCS, address, value)
		require.NoError(t, err)
		return table, reference
	}

	t.Run("Adding a second address, anycasting to first one returns correct value",
		func(t *testing.T) {
			table, _ := prepare(t)
			_, err := table.Register(addr.SvcCS, diffIpSamePortAddress, otherValue)
			assert.NoError(t, err)
			retValues := table.Lookup(addr.SvcCS, address.IP)
			assert.Equal(t, []interface{}{value}, retValues)
		})
	t.Run("Freeing the reference yields nil on anycast", func(t *testing.T) {
		table, reference := prepare(t)
		reference.Free()
		retValues := table.Lookup(addr.SvcCS, nil)
		assert.Empty(t, retValues)

		// Check double free panicks
		assert.Panics(t, func() { reference.Free() })

		_, err := table.Register(addr.SvcCS, address, value)
		assert.NoError(t, err)
	})
}
func TestSVCTableTwoItems(t *testing.T) {
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	sameIpDiffPortAddress := &net.UDPAddr{IP: address.IP, Port: address.Port + 1}
	value := "test value"
	otherValue := "other test value"

	prepare := func(t *testing.T) SVCTable {
		table := NewSVCTable()
		_, err := table.Register(addr.SvcCS, address, value)
		require.NoError(t, err)
		_, err = table.Register(addr.SvcCS, sameIpDiffPortAddress, otherValue)
		require.NoError(t, err)
		return table
	}

	t.Run("The anycasts will cycle between the values", func(t *testing.T) {
		table := prepare(t)
		retValues := table.Lookup(addr.SvcCS, address.IP)
		assert.Equal(t, []interface{}{value}, retValues)
		otherRetValue := table.Lookup(addr.SvcCS, address.IP)
		assert.Equal(t, []interface{}{otherValue}, otherRetValue)
	})

	t.Run("A multicast will return both values", func(t *testing.T) {
		table := prepare(t)
		retValues := table.Lookup(addr.SvcCS.Multicast(), address.IP)
		assert.Equal(t, len(retValues), 2)
	})
}

func TestSVCTableMulticastTwoAddresses(t *testing.T) {
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	diffAddress := &net.UDPAddr{IP: net.IP{10, 5, 6, 7}, Port: address.Port}
	value := "test value"
	otherValue := "other test value"

	table := NewSVCTable()
	_, err := table.Register(addr.SvcCS, address, value)
	require.NoError(t, err)
	_, err = table.Register(addr.SvcCS, diffAddress, otherValue)
	require.NoError(t, err)

	retValues := table.Lookup(addr.SvcCS.Multicast(), address.IP)
	assert.ElementsMatch(t, []interface{}{otherValue, value}, retValues)
}

func TestSVCTableStress(t *testing.T) {
	registrationCount := 1000
	// Generate many random registrations, then free all
	table := NewSVCTable()
	references := runRandomRegistrations(registrationCount, table)
	for _, ref := range references {
		ref.Free()
	}
	// then generate some more, and free again
	references = runRandomRegistrations(registrationCount, table)
	for _, ref := range references {
		ref.Free()
	}
	t.Run("Table should be empty", func(t *testing.T) {
		assert.Equal(t, table.String(), "map[]")
	})
}

func runRandomRegistrations(count int, table SVCTable) []Reference {
	var references []Reference
	for i := 0; i < count; i++ {
		ref, err := table.Register(addr.SvcCS, getRandomUDPAddress(), getRandomValue())
		if err == nil {
			references = append(references, ref)
		}
	}
	return references
}

func TestSVCTableFree(t *testing.T) {
	ip := net.IP{10, 2, 3, 4}
	prepare := func(t *testing.T) (SVCTable, []Reference) {
		// Prepare a table with three entries on the same IP
		table := NewSVCTable()
		addressOne := &net.UDPAddr{IP: ip, Port: 10080}
		refOne, err := table.Register(addr.SvcCS, addressOne, "1")
		require.NoError(t, err)
		addressTwo := &net.UDPAddr{IP: ip, Port: 10081}
		refTwo, err := table.Register(addr.SvcCS, addressTwo, "2")
		require.NoError(t, err)
		addressThree := &net.UDPAddr{IP: ip, Port: 10082}
		refThree, err := table.Register(addr.SvcCS, addressThree, "3")
		require.NoError(t, err)
		return table, []Reference{refOne, refTwo, refThree}
	}
	for i := 0; i < 3; i++ {
		addrremainone := strconv.Itoa((i+1)%3 + 1)
		addrremaintwo := strconv.Itoa((i+2)%3 + 1)
		name := fmt.Sprintf("Addresses %s and %s must remain", addrremainone, addrremaintwo)
		t.Run(name, func(t *testing.T) {
			table, refs := prepare(t)
			refs[i].Free()
			retValues := table.Lookup(addr.SvcCS.Multicast(), ip)
			assert.ElementsMatch(t, []interface{}{addrremainone, addrremaintwo}, retValues)
			checkAnyCastCycles(t,
				func() []interface{} { return table.Lookup(addr.SvcCS, ip) },
				[]string{addrremainone, addrremaintwo})

			if i == 2 {
				// removing address 1, after removing address 3, should leave us with address 2
				refs[0].Free()
				retValues := table.Lookup(addr.SvcCS.Multicast(), ip)
				assert.ElementsMatch(t, []interface{}{"2"}, retValues)
				checkAnyCastCycles(t,
					func() []interface{} { return table.Lookup(addr.SvcCS, ip) },
					[]string{"2"})
			}
		})
	}

}

func checkAnyCastCycles(t *testing.T, lookup func() []interface{}, expected []string) {
	t.Helper()
	firstRes := lookup()[0].(string)
	startIndex := -1
	for i := range expected {
		if expected[i] == firstRes {
			startIndex = i + 1
			break
		}
	}
	if startIndex == -1 {
		t.Fatalf("Initial value %s not in expected (%v)", firstRes, expected)
	}
	for cnt := 0; cnt < len(expected)+1; cnt++ {
		idx := (startIndex + cnt) % len(expected)
		res := lookup()[0].(string)
		if res != expected[idx] {
			t.Fatalf("Value %s was not expected in (%v)", res, expected)
		}
	}
}

func TestSVCTableWildcard(t *testing.T) {
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	value := "test value"

	table := NewSVCTable()
	reference, err := table.Register(addr.SvcWildcard, address, value)
	require.NoError(t, err)
	defer reference.Free()

	testCases := map[string]struct {
		Address           addr.HostSVC
		LookupResultCount int
	}{
		"cs": {
			Address:           addr.SvcCS.Multicast(),
			LookupResultCount: 1,
		},
		"ds": {
			Address:           addr.SvcDS.Multicast(),
			LookupResultCount: 1,
		},
		"sig": {
			Address:           addr.SvcSIG.Multicast(),
			LookupResultCount: 0,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			retValues := table.Lookup(tc.Address, nil)
			assert.Equal(t, tc.LookupResultCount, len(retValues))
		})
	}
}

func TestSVCTableWildcardFree(t *testing.T) {
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	value := "test value"

	table := NewSVCTable()
	reference, err := table.Register(addr.SvcWildcard, address, value)
	require.NoError(t, err)
	reference.Free()

	assert.Equal(t, 0, len(table.Lookup(addr.SvcCS, nil)))
	assert.Equal(t, 0, len(table.Lookup(addr.SvcDS, nil)))
}

func TestSVCTableWildcardRollback(t *testing.T) {
	// If any SVC registration fails on a wildcard, none should remain
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	value := "test value"

	table := NewSVCTable()

	testCases := map[string]struct {
		RegisteredAddress   addr.HostSVC
		LookupResultCSCount int
		LookupResultDSCount int
	}{
		"cs": {
			RegisteredAddress:   addr.SvcCS,
			LookupResultCSCount: 1,
			LookupResultDSCount: 0,
		},
		"ds": {
			RegisteredAddress:   addr.SvcDS,
			LookupResultCSCount: 0,
			LookupResultDSCount: 1,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			reference, err := table.Register(tc.RegisteredAddress, address, value)
			require.NoError(t, err)
			defer reference.Free()

			_, err = table.Register(addr.SvcWildcard, address, value)
			assert.Error(t, err)

			assert.Equal(t, tc.LookupResultCSCount, len(table.Lookup(addr.SvcCS, nil)))
			assert.Equal(t, tc.LookupResultDSCount, len(table.Lookup(addr.SvcDS, nil)))
		})
	}
}
