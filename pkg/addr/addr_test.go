// Copyright 2023 SCION Association
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
	"encoding"
	"flag"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
)

func ExampleParseAddr() {
	a, err := addr.ParseAddr("6-ffaa:0:123,198.51.100.1")
	fmt.Printf("ia: %v, host type: %v, host: %v, err: %v\n", a.IA, a.Host.Type(), a.Host, err)
	// Output: ia: 6-ffaa:0:123, host type: IP, host: 198.51.100.1, err: <nil>
}

func ExampleParseAddr_svc() {
	a, err := addr.ParseAddr("6-ffaa:0:123,CS")
	fmt.Printf("ia: %v, host type: %v, host: %v, err: %v\n", a.IA, a.Host.Type(), a.Host, err)
	// Output: ia: 6-ffaa:0:123, host type: SVC, host: CS, err: <nil>
}

func TestParseAddr(t *testing.T) {
	invalid := []string{
		"",
		",",
		"a",
		"0-0::",
		"0-0,::,",
		"1,ffaa:0:1101::",
		"65536-1,ff00::1",
		"[1-ffaa:0:1101,127.0.0.1]",
	}
	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			_, err := addr.ParseAddr(s)
			assert.Error(t, err)
		})
		t.Run("unmarshal "+s, func(t *testing.T) {
			var a addr.Addr
			var u encoding.TextUnmarshaler = &a
			err := u.UnmarshalText([]byte(s))
			assert.Error(t, err)
			assert.Equal(t, addr.Addr{}, a)
		})
		t.Run("set "+s, func(t *testing.T) {
			var a addr.Addr
			var v flag.Value = &a
			err := v.Set(s)
			assert.Error(t, err)
			assert.Equal(t, addr.Addr{}, a)
		})
	}

	valid := map[string]addr.Addr{
		"0-0,::": {
			IA:   addr.MustIAFrom(0, 0),
			Host: addr.HostIP(netip.AddrFrom16([16]byte{})),
		},
		"0-0,0.0.0.0": {
			IA:   addr.MustIAFrom(0, 0),
			Host: addr.HostIP(netip.AddrFrom4([4]byte{})),
		},
		"1-ffaa:0:1101,::1": {
			IA: addr.MustIAFrom(1, 0xffaa_0000_1101),
			Host: addr.HostIP(netip.AddrFrom16(
				[16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			)),
		},
		"1-ffaa:0:1101,127.0.0.1": {
			IA:   addr.MustIAFrom(1, 0xffaa_0000_1101),
			Host: addr.HostIP(netip.AddrFrom4([4]byte{127, 0, 0, 1})),
		},
		"1-ffaa:0:1101,CS": {
			IA:   addr.MustIAFrom(1, 0xffaa_0000_1101),
			Host: addr.HostSVC(addr.SvcCS),
		},
		"65535-1,ff00::1": {
			IA: addr.MustIAFrom(65535, 1),
			Host: addr.HostIP(netip.AddrFrom16(
				[16]byte{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			)),
		},
		"1-1:fcd1:1,::ffff:192.0.2.128": {
			IA: addr.MustIAFrom(1, 0x0001_fcd1_0001),
			Host: addr.HostIP(netip.AddrFrom16(
				[16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 128},
			)),
		},
	}
	for s, expected := range valid {
		t.Run(s, func(t *testing.T) {
			a, err := addr.ParseAddr(s)
			require.NoError(t, err)
			assert.Equal(t, expected, a)
		})
		t.Run("unmarshal "+s, func(t *testing.T) {
			var a addr.Addr
			var u encoding.TextUnmarshaler = &a
			err := u.UnmarshalText([]byte(s))
			require.NoError(t, err)
			assert.Equal(t, expected, a)
		})
		t.Run("set "+s, func(t *testing.T) {
			var a addr.Addr
			var v flag.Value = &a
			err := v.Set(s)
			require.NoError(t, err)
			assert.Equal(t, expected, a)
		})
	}
}

func TestParseAddrPort(t *testing.T) {
	invalid := []string{
		"",
		"[]",
		"[]:",
		"[0-0,::]:65536",
		"[0-0,::]:http",
		"[0-0,::]:a",
		"[1-ffaa:0:1101,127.0.0.1]",
		"[1-ffaa:0:1101,127.0.0.1]:0xff",
		"[1-ffaa:0:1101,127.0.0.1]:ff",
		"[1-ffaa:0:1101,127.0.0.1]:-1",
		"[1-ffaa:0:1101,127.0.0.1]:666666",
	}
	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			_, _, err := addr.ParseAddrPort(s)
			assert.Error(t, err)
		})
	}

	valid := map[string]struct {
		IA   addr.IA
		Host addr.Host
		Port uint16
	}{
		"[0-0,::]:0": {
			IA:   addr.MustIAFrom(0, 0),
			Host: addr.HostIP(netip.AddrFrom16([16]byte{})),
			Port: 0,
		},
		"[0-0,::]:65535": {
			IA:   addr.MustIAFrom(0, 0),
			Host: addr.HostIP(netip.AddrFrom16([16]byte{})),
			Port: 65535,
		},
		"[0-0,0.0.0.0]:1234": {
			IA:   addr.MustIAFrom(0, 0),
			Host: addr.HostIP(netip.AddrFrom4([4]byte{})),
			Port: 1234,
		},
		"[1-ffaa:0:1101,::1]:54321": {
			IA: addr.MustIAFrom(1, 0xffaa_0000_1101),
			Host: addr.HostIP(netip.AddrFrom16(
				[16]byte{15: 1},
			)),
			Port: 54321,
		},
		"[1-ffaa:0:1101,127.0.0.1]:010": {
			IA:   addr.MustIAFrom(1, 0xffaa_0000_1101),
			Host: addr.HostIP(netip.AddrFrom4([4]byte{127, 0, 0, 1})),
			Port: 10,
		},
		"[1-ffaa:0:1101,CS]:42": {
			IA:   addr.MustIAFrom(1, 0xffaa_0000_1101),
			Host: addr.HostSVC(addr.SvcCS),
			Port: 42,
		},
		"[65535-1,ff00::1]:8888": {
			IA: addr.MustIAFrom(65535, 1),
			Host: addr.HostIP(netip.AddrFrom16(
				[16]byte{0: 0xff, 15: 1},
			)),
			Port: 8888,
		},
		"[1-1:fcd1:1,::ffff:192.0.2.128]:0000000000000000000080": {
			IA: addr.MustIAFrom(1, 0x0001_fcd1_0001),
			Host: addr.HostIP(netip.AddrFrom16(
				[16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 128},
			)),
			Port: 80,
		},
	}

	for s, expected := range valid {
		t.Run(s, func(t *testing.T) {
			a, port, err := addr.ParseAddrPort(s)
			require.NoError(t, err)
			assert.Equal(t, addr.Addr{IA: expected.IA, Host: expected.Host}, a)
			assert.Equal(t, expected.Port, port)

			fmted := addr.FormatAddrPort(a, port)
			if !strings.Contains(s, "]:0") { // skip cases where port has leading 0s
				assert.Equal(t, s, fmted)
			}
		})
	}
}
