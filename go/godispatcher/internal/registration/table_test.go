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

	table := NewTable(minPort, maxPort)
	assert.Equal(t, table.Size(), 0, "initial size is 0")

	t.Log("Register with no public address fails")
	ref, err := table.Register(nil, nil, addr.SvcNone, dummyValue)
	assert.Error(t, err)
	assert.Nil(t, ref)

	t.Log("Register with zero public IPv4 address succeeds")
	p1 := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 80,
	}
	ref, err = table.Register(p1, nil, addr.SvcNone, dummyValue)
	assert.NoError(t, err)
	assert.NotNil(t, ref)

	t.Log("Register with zero public IPv6 address succeeds")
	p2 := &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: 80,
	}
	ref, err = table.Register(p2, nil, addr.SvcNone, dummyValue)
	assert.NoError(t, err)
	assert.NotNil(t, ref)

	t.Log("Register with public address with port, no bind, no svc succeeds")
	p3 := &net.UDPAddr{
		IP:   net.IP{192, 0, 5, 1},
		Port: 8080,
	}
	ref, err = table.Register(p3, nil, addr.SvcNone, dummyValue)
	assert.NoError(t, err)
	assert.NotNil(t, ref)

	t.Log("Register with public address without port, no bind, no svc succeeds")
	p4 := &net.UDPAddr{
		IP: net.IP{192, 0, 9, 1},
	}
	ref, err = table.Register(p4, nil, addr.SvcNone, dummyValue)
	assert.NoError(t, err)
	assert.NotNil(t, ref)

	t.Log("Register with public address, bind, no svc fails")
	p5 := &net.UDPAddr{
		IP:   net.IP{192, 0, 20, 1},
		Port: 8880,
	}
	b5 := net.IP{10, 2, 3, 4}
	ref, err = table.Register(p5, b5, addr.SvcNone, dummyValue)
	assert.Error(t, err)
	assert.Nil(t, ref)

	t.Log("Register with public address, no bind, svc succeeds")
	p6 := &net.UDPAddr{
		IP:   net.IP{192, 0, 22, 1},
		Port: 8889,
	}
	ref, err = table.Register(p6, nil, addr.SvcPS, dummyValue)
	assert.NoError(t, err)
	assert.NotNil(t, ref)

	t.Log("Register with zero bind IPv4 address fails")
	p7 := &net.UDPAddr{
		IP:   net.IP{192, 0, 23, 1},
		Port: 8888,
	}
	ref, err = table.Register(p7, net.IPv4zero, addr.SvcCS, dummyValue)
	assert.Error(t, err)
	assert.Nil(t, ref)

	t.Log("Register with zero bind IPv6 address fails")
	p8 := &net.UDPAddr{
		IP:   net.IP{192, 0, 23, 1},
		Port: 8888,
	}
	ref, err = table.Register(p8, net.IPv6zero, addr.SvcCS, dummyValue)
	assert.Error(t, err)
	assert.Nil(t, ref)

	t.Log("Register with public address, bind, svc succeeds")
	p9 := &net.UDPAddr{
		IP:   net.IP{192, 0, 23, 1},
		Port: 8888,
	}
	b9 := net.IP{10, 2, 3, 4}

	ref, err = table.Register(p9, b9, addr.SvcCS, dummyValue)
	assert.NoError(t, err)
	assert.NotNil(t, ref)
}

func TestRegisterOnlyPublic(t *testing.T) {
	table := NewTable(minPort, maxPort)
	assert.Equal(t, table.Size(), 0, "initial size is 0")

	t.Log("Given a table with a public address registration")
	t.Run("Free reference, size is 0", func(t *testing.T) {
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
