// Copyright 2021 ETH Zurich, Anapaya Systems
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

package addr_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
)

func TestHostFromRaw(t *testing.T) {
	testCases := map[string]struct {
		input        []byte
		addrType     addr.HostAddrType
		expected     addr.HostAddr
		errAssertion assert.ErrorAssertionFunc
	}{
		"nil IPv4": {
			addrType:     addr.HostTypeIPv4,
			errAssertion: assert.Error,
		},
		"short IPv4": {
			input:        make([]byte, 3),
			addrType:     addr.HostTypeIPv4,
			errAssertion: assert.Error,
		},
		"valid IPv4": {
			input:        []byte{127, 0, 0, 1},
			addrType:     addr.HostTypeIPv4,
			expected:     addr.HostFromIP(net.IPv4(127, 0, 0, 1)),
			errAssertion: assert.NoError,
		},
		"nil IPv6": {
			addrType:     addr.HostTypeIPv6,
			errAssertion: assert.Error,
		},
		"short IPv6": {
			input:        make([]byte, 14),
			addrType:     addr.HostTypeIPv6,
			errAssertion: assert.Error,
		},
		"valid IPv6": {
			input:        net.ParseIP("dead::beef"),
			addrType:     addr.HostTypeIPv6,
			expected:     addr.HostFromIP(net.ParseIP("dead::beef")),
			errAssertion: assert.NoError,
		},
		"nil SVC": {
			addrType:     addr.HostTypeSVC,
			errAssertion: assert.Error,
		},
		"short SVC": {
			input:        make([]byte, 1),
			addrType:     addr.HostTypeSVC,
			errAssertion: assert.Error,
		},
		"valid SVC": {
			input:        addr.SvcDS.Pack(),
			addrType:     addr.HostTypeSVC,
			expected:     addr.SvcDS,
			errAssertion: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			got, err := addr.HostFromRaw(tc.input, tc.addrType)
			tc.errAssertion(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}
