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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
)

var (
	public = &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 80}
	value  = "test value"
	ia     = xtest.MustParseIA("1-ff00:0:1")
)

func TestIATable(t *testing.T) {

	t.Run("Given a table with one entry that is only public and no svc", func(t *testing.T) {
		table := NewIATable(minPort, maxPort)
		ref, err := table.Register(ia, public, nil, addr.SvcNone, value)
		assert.NoError(t, err)
		assert.NotNil(t, ref)
		t.Run("lookups for the same AS", func(t *testing.T) {
			retValue, ok := table.LookupPublic(ia, public)
			assert.True(t, ok)
			assert.Equal(t, retValue, value)
			retValues := table.LookupService(ia, addr.SvcCS, net.IP{192, 0, 2, 1})
			assert.Empty(t, retValues)
		})

		t.Run("lookups for a different AS", func(t *testing.T) {
			otherIA := xtest.MustParseIA("1-ff00:0:2")
			retValue, ok := table.LookupPublic(otherIA, public)
			assert.False(t, ok)
			assert.Nil(t, retValue)
			retValues := table.LookupService(otherIA, addr.SvcCS, net.IP{192, 0, 2, 1})
			assert.Empty(t, retValues)
		})

		t.Run("calling free twice panics", func(t *testing.T) {
			ref.Free()
			require.Panics(t, ref.Free)
		})
	})

	t.Run("Given a table with one entry that is only public and svc", func(t *testing.T) {
		table := NewIATable(minPort, maxPort)
		t.Run("lookups for the same AS works", func(t *testing.T) {
			ref, err := table.Register(ia, public, nil, addr.SvcCS, value)
			assert.NoError(t, err)
			assert.NotNil(t, ref)
			retValue, ok := table.LookupPublic(ia, public)
			assert.True(t, ok)
			assert.Equal(t, retValue, value)
			retValues := table.LookupService(ia, addr.SvcCS, net.IP{192, 0, 2, 1})
			assert.Equal(t, retValues, []interface{}{value})
		})
	})
}

func TestIATableRegister(t *testing.T) {
	t.Log("Given an empty table")

	t.Run("ISD zero is error", func(t *testing.T) {
		table := NewIATable(minPort, maxPort)
		ref, err := table.Register(addr.MustIAFrom(0, 1), public, nil, addr.SvcNone, value)
		assert.EqualError(t, err, ErrBadISD.Error())
		assert.Nil(t, ref)
	})

	t.Run("AS zero is error", func(t *testing.T) {
		table := NewIATable(minPort, maxPort)
		ref, err := table.Register(addr.MustIAFrom(1, 0), public, nil, addr.SvcNone, value)
		assert.EqualError(t, err, ErrBadAS.Error())
		assert.Nil(t, ref)
	})

	t.Run("for a good AS number", func(t *testing.T) {
		ia := xtest.MustParseIA("1-ff00:0:1")
		t.Run("already registered ports will cause error", func(t *testing.T) {
			table := NewIATable(minPort, maxPort)
			_, err := table.Register(ia, public, nil, addr.SvcNone, value)
			require.NoError(t, err)
			ref, err := table.Register(ia, public, nil, addr.SvcNone, value)
			assert.Error(t, err)
			assert.Nil(t, ref)
		})

		t.Run("good ports will return success", func(t *testing.T) {
			table := NewIATable(minPort, maxPort)
			ref, err := table.Register(ia, public, nil, addr.SvcNone, value)
			assert.NoError(t, err)
			assert.NotNil(t, ref)
		})
	})
}

func TestIATableSCMPRegistration(t *testing.T) {
	table := NewIATable(minPort, maxPort)

	t.Log("Given a reference to an IATable registration")
	ref, err := table.Register(ia, public, nil, addr.SvcNone, value)
	require.NoError(t, err)
	v, ok := table.LookupID(ia, 42)
	assert.False(t, ok, "Performing SCMP lookup fails")
	assert.Nil(t, v)
	err = ref.RegisterID(42)
	assert.NoError(t, err, "Registering an SCMP ID on the reference succeeds")
}

func TestIATableSCMPExistingRegistration(t *testing.T) {

	t.Run("Registering a second SCMP ID on the same reference succeeds", func(t *testing.T) {
		table := NewIATable(minPort, maxPort)
		ref, err := table.Register(ia, public, nil, addr.SvcNone, value)
		require.NoError(t, err)
		t.Log("Given an existing SCMP General ID registration")
		err = ref.RegisterID(42)
		require.NoError(t, err)

		t.Log("Performing an SCMP lookup on the same IA succeeds")
		retValue, ok := table.LookupID(ia, 42)
		assert.True(t, ok)
		assert.Equal(t, retValue, value)

		t.Log("Performing an SCMP lookup on a different IA fails")
		retValue, ok = table.LookupID(xtest.MustParseIA("1-ff00:0:2"), 42)
		assert.False(t, ok)
		assert.Nil(t, retValue)

		t.Log("Freeing the reference makes lookup fail")
		ref.Free()
		retValue, ok = table.LookupID(ia, 42)
		assert.False(t, ok)
		assert.Nil(t, retValue)
	})

	t.Run("Registering a second SCMP ID on the same reference succeeds", func(t *testing.T) {
		table := NewIATable(minPort, maxPort)
		ref, err := table.Register(ia, public, nil, addr.SvcNone, value)
		require.NoError(t, err)
		t.Log("Given an existing SCMP General ID registration")
		err = ref.RegisterID(42)
		require.NoError(t, err)
		err = ref.RegisterID(43)
		assert.NoError(t, err)

		t.Log("Freeing the reference makes lookup on first registered id fail")
		ref.Free()
		retValue, ok := table.LookupID(ia, 42)
		assert.False(t, ok)
		assert.Nil(t, retValue)
	})
}
