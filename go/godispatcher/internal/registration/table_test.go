// Copyright 2018 ETH Zurich
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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
)

var dummyValue = "test value"

func TestRegister(t *testing.T) {
	tests := map[string]struct {
		a   *net.UDPAddr
		b   net.IP
		svc addr.HostSVC
		af  assert.ErrorAssertionFunc
	}{
		"no public address fails": {
			a:   nil,
			svc: addr.SvcNone,
			af:  assert.Error,
		},
		"zero public IPv4 address succeeds": {
			a:   &net.UDPAddr{IP: net.IPv4zero, Port: 80},
			svc: addr.SvcNone,
			af:  assert.NoError,
		},
		"zero public IPv6 address succeeds": {
			a:   &net.UDPAddr{IP: net.IPv6zero, Port: 80},
			svc: addr.SvcNone,
			af:  assert.NoError,
		},
		"public address with port, no bind, no svc succeeds": {
			a:  &net.UDPAddr{IP: net.IP{192, 0, 5, 1}, Port: 8080},
			af: assert.NoError,
		},
		"public address without port, no bind, no svc succeeds": {
			a:   &net.UDPAddr{IP: net.IP{192, 0, 9, 1}},
			svc: addr.SvcNone,
			af:  assert.NoError,
		},
		"public address, bind, no svc fails": {
			a:   &net.UDPAddr{IP: net.IP{192, 0, 20, 1}, Port: 8880},
			b:   net.IP{10, 2, 3, 4},
			svc: addr.SvcNone,
			af:  assert.Error,
		},

		"public address, no bind, svc succeeds": {
			a:   &net.UDPAddr{IP: net.IP{192, 0, 22, 1}, Port: 8889},
			svc: addr.SvcPS,
			af:  assert.NoError,
		},

		"zero bind IPv4 address fails": {
			a:   &net.UDPAddr{IP: net.IP{192, 0, 23, 1}, Port: 8888},
			b:   net.IPv4zero,
			svc: addr.SvcCS,
			af:  assert.Error,
		},

		"zero bind IPv6 address fails": {
			a:   &net.UDPAddr{IP: net.IP{192, 0, 23, 1}, Port: 8888},
			b:   net.IPv6zero,
			svc: addr.SvcCS,
			af:  assert.Error,
		},
		"public address, bind, svc succeeds": {
			a:   &net.UDPAddr{IP: net.IP{192, 0, 23, 1}, Port: 8888},
			b:   net.IP{10, 2, 3, 4},
			svc: addr.SvcCS,
			af:  assert.NoError,
		},
	}

	for n, tc := range tests {
		t.Run(n, func(t *testing.T) {
			table := NewTable(minPort, maxPort)
			assert.Equal(t, table.Size(), 0, "initial size is 0")
			ref, err := table.Register(tc.a, tc.b, tc.svc, dummyValue)
			tc.af(t, err)
			if err != nil {
				assert.Nil(t, ref)
				return
			}
			assert.NotNil(t, ref)
		})
	}

	table := NewTable(minPort, maxPort)
	assert.Equal(t, table.Size(), 0, "initial size is 0")

}

func TestRegisterOnlyPublic(t *testing.T) {

	t.Run("Free reference, size is 0", func(t *testing.T) {
		t.Log("Given a table with a public address registration")
		table := NewTable(minPort, maxPort)
		assert.Equal(t, table.Size(), 0, "initial size is 0")
		public := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 80}
		ref, err := table.Register(public, nil, addr.SvcNone, dummyValue)
		require.NoError(t, err)
		assert.Equal(t, table.Size(), 1, "size is 1")
		assert.NotNil(t, ref)

		t.Log("Lookup is successful")
		retValue, ok := table.LookupPublic(public)
		assert.True(t, ok)
		assert.Equal(t, retValue, dummyValue)

		ref.Free()
		assert.Equal(t, table.Size(), 0, "size is 0")
		assert.Panics(t, ref.Free, "Free same reference again, panic")
		retValue, ok = table.LookupPublic(public)
		assert.False(t, ok, "lookup should fail")
		assert.Nil(t, retValue)
	})

	t.Run("Register", func(t *testing.T) {
		t.Log("Given a table with a public address registration")
		table := NewTable(minPort, maxPort)
		assert.Equal(t, table.Size(), 0, "initial size is 0")
		public := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 80}
		ref, err := table.Register(public, nil, addr.SvcNone, dummyValue)
		require.NoError(t, err)
		assert.Equal(t, table.Size(), 1, "size is 1")
		assert.NotNil(t, ref)

		t.Log("Lookup is successful")
		retValue, ok := table.LookupPublic(public)
		assert.True(t, ok)
		assert.Equal(t, retValue, dummyValue)

		t.Log("Register same address returns error")
		ref, err = table.Register(public, nil, addr.SvcNone, dummyValue)
		assert.Error(t, err)
		assert.Nil(t, ref)

		t.Log("Register 0.0.0.0, error due to overlap")
		public = &net.UDPAddr{IP: net.IPv4zero, Port: 80}
		ref, err = table.Register(public, nil, addr.SvcNone, dummyValue)
		assert.Error(t, err)
		assert.Nil(t, ref)

		t.Log("Register ::, success")
		public = &net.UDPAddr{IP: net.IPv6zero, Port: 80}
		ref, err = table.Register(public, nil, addr.SvcNone, dummyValue)
		assert.NoError(t, err)
		assert.NotNil(t, ref)
	})
}

func TestRegisterPublicAndSVC(t *testing.T) {
	table := NewTable(minPort, maxPort)
	assert.Equal(t, table.Size(), 0, "size is 0")

	t.Log("Given a table with a public address registration")
	p := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 80}
	_, err := table.Register(p, nil, addr.SvcCS, dummyValue)
	require.NoError(t, err)
	assert.Equal(t, table.Size(), 1, "size is 1")

	t.Log("Public lookup is successful")
	retValue, ok := table.LookupPublic(p)
	assert.True(t, ok)
	assert.Equal(t, retValue, dummyValue)

	t.Log("SVC lookup is successful (bind inherits from public)")
	retValues := table.LookupService(addr.SvcCS, p.IP)
	assert.Equal(t, retValues, []interface{}{dummyValue})
}

func TestRegisterWithBind(t *testing.T) {
	table := NewTable(minPort, maxPort)

	t.Log("Given a table with a bind address registration")
	p := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 80}
	bind := net.IP{10, 2, 3, 4}
	ref, err := table.Register(p, bind, addr.SvcCS, dummyValue)
	require.NoError(t, err)
	assert.NotNil(t, ref)
	assert.Equal(t, table.Size(), 1, "size is 1")

	t.Log("Public lookup is successful")
	retValue, ok := table.LookupPublic(p)
	assert.True(t, ok)
	assert.Equal(t, retValue, dummyValue)

	t.Log("SVC lookup is successful")
	retValues := table.LookupService(addr.SvcCS, bind)
	assert.Equal(t, retValues, []interface{}{dummyValue})

	t.Log("Bind lookup on different svc fails")
	retValues = table.LookupService(addr.SvcBS, bind)
	assert.Empty(t, retValues)

	t.Log("Colliding binds returns error, and public port is released")
	otherPublic := &net.UDPAddr{IP: net.IP{192, 0, 2, 2}, Port: 80}
	_, err = table.Register(otherPublic, bind, addr.SvcCS, dummyValue)
	assert.Error(t, err)
	assert.Equal(t, table.Size(), 1, "size is 1")
	_, err = table.Register(otherPublic, nil, addr.SvcNone, dummyValue)
	assert.NoError(t, err)

	t.Log("Freeing the entry allows for reregistration")
	ref.Free()
	_, err = table.Register(p, bind, addr.SvcCS, dummyValue)
	assert.NoError(t, err)
}
