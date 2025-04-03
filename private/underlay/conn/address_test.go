// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
// Copyright 2025 SCION Association
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

package conn

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddresses(t *testing.T) {
	testCases := []struct {
		Name            string
		Raw             string
		ExpectedAddress netip.AddrPort
		ExpectedError   assert.ErrorAssertionFunc
	}{
		{
			Name:          "Empty",
			Raw:           "",
			ExpectedError: assert.Error,
		},
		{
			Name:            "Port only",
			Raw:             ":42",
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.AddrPortFrom(netip.Addr{}, 42),
		},
		{
			Name:            "Good IPv4",
			Raw:             "127.0.0.1:42",
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.MustParseAddrPort("127.0.0.1:42"),
		},
		{
			Name:            "Good IPv6",
			Raw:             "[::1]:42",
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.MustParseAddrPort("[::1]:42"),
		},
		{
			Name:            "Good IPv6 with zone",
			Raw:             "[::1%some-zone]:42",
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.MustParseAddrPort(`[::1%some-zone]:42`),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			topoBRAddr, err := ResolveAddrPortOrPort(tc.Raw)
			tc.ExpectedError(t, err)
			assert.Equal(t, tc.ExpectedAddress, topoBRAddr)
		})
	}
}
