// Copyright 2026 Anapaya Systems
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

package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/testing/clab/e2e"
)

func TestLoadEndpoints(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scion.clab.yml"), []byte(`
name: scion
topology:
  nodes:
    1-ff00_0_110-host-1:
      mgmt-ipv4: 10.0.1.1
    1-ff00_0_110-host-A:
      mgmt-ipv4: 10.0.1.2
    1-ff00_0_111-host-1:
      mgmt-ipv6: fd00:f00d:cafe:2::1
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sciond_addresses.json"), []byte(`{
  "1-ff00:0:110": "10.0.1.1",
  "1-ff00:0:111": "fd00:f00d:cafe:2::1"
}`), 0o644))

	eps, err := e2e.LoadEndpoints(dir, "scion")
	require.NoError(t, err)
	require.Len(t, eps, 2)

	// Matched by management IP (host-A is not the control host for 110).
	assert.Equal(t, "clab-scion-1-ff00_0_110-host-1", eps[0].Container)
	assert.Equal(t, "1-ff00:0:110,10.0.1.1", eps[0].SCIONAddr())
	assert.Equal(t, "10.0.1.1:30255", eps[0].SciondAddr())
	assert.Equal(t, "10.0.1.1:40000", eps[0].ListenAddr(40000))
	assert.Equal(t, "1-ff00:0:110,10.0.1.1:40000", eps[0].RemoteAddr(40000))

	// IPv6 host is bracketed in host:port forms, but not in the SCION address.
	assert.Equal(t, "1-ff00:0:111,fd00:f00d:cafe:2::1", eps[1].SCIONAddr())
	assert.Equal(t, "[fd00:f00d:cafe:2::1]:30255", eps[1].SciondAddr())
	assert.Equal(t, "1-ff00:0:111,[fd00:f00d:cafe:2::1]:40000", eps[1].RemoteAddr(40000))
}

func TestLoadEndpointsMissingNode(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scion.clab.yml"), []byte(`
name: scion
topology:
  nodes:
    1-ff00_0_110-host-1:
      mgmt-ipv4: 10.0.1.1
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sciond_addresses.json"),
		[]byte(`{"1-ff00:0:110": "10.9.9.9"}`), 0o644))

	_, err := e2e.LoadEndpoints(dir, "scion")
	assert.Error(t, err)
}
