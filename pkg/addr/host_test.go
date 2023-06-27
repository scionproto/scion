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
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
)

func ExampleHost() {
	hs := []addr.Host{
		{},
		addr.HostIP(netip.MustParseAddr("::1")),
		addr.HostIP(netip.AddrFrom4([4]byte{198, 51, 100, 1})),
		addr.HostSVC(addr.SvcCS),
	}
	for _, h := range hs {
		fmt.Printf("h: %q, h.Type(): %q", h, h.Type())
		switch h.Type() {
		case addr.HostTypeIP:
			fmt.Printf(", h.IP().Is4(): %v", h.IP().Is4())
		case addr.HostTypeSVC:
			fmt.Printf(", h.SVC().IsMulticast(): %v", h.SVC().IsMulticast())
		default:
			fmt.Printf(", h == addr.Host{}: %v", h == addr.Host{})
		}
		fmt.Println()
	}

	// Use Host as map key:
	stuff := make(map[addr.Host]struct{})
	for _, h := range hs {
		stuff[h] = struct{}{}
	}
	_, hasSvcCS := stuff[addr.HostSVC(addr.SvcCS)]
	_, hasSvcDS := stuff[addr.HostSVC(addr.SvcDS)]
	fmt.Printf("has SvcCS: %v, has SvcDS: %v", hasSvcCS, hasSvcDS)

	// Output:
	// h: "<None>", h.Type(): "None", h == addr.Host{}: true
	// h: "::1", h.Type(): "IP", h.IP().Is4(): false
	// h: "198.51.100.1", h.Type(): "IP", h.IP().Is4(): true
	// h: "CS", h.Type(): "SVC", h.SVC().IsMulticast(): false
	// has SvcCS: true, has SvcDS: false
}

func TestHostStructSize(t *testing.T) {
	if runtime.GOARCH != `amd64` {
		t.SkipNow()
	}
	ipv6 := 16
	zonePtr := 8
	svc := 2
	typ := 1
	padding := 5
	expected := ipv6 + zonePtr + svc + typ + padding

	sizeofHost := int(reflect.TypeOf(addr.Host{}).Size())
	assert.Equal(t, expected, sizeofHost)
}

func TestParseHost(t *testing.T) {
	invalid := []string{
		"",
		"x",
		"512.0.0.1",
		"10.1234567",
		"::ffff1",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334:1", // too long
		" ::1",
		"::1 ",
		"localhost",
		"CS_X", // almost a service addr
	}
	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			_, err := addr.ParseHost(s)
			assert.Error(t, err)
		})
	}

	ipv6 := []string{
		"::",
		"::1",
		"::ff02:1",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		"fe80::1ff:fe23:4567:890a%eth2",
		"::ffff:192.0.2.128",
		"ff00::",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	}
	for _, s := range ipv6 {
		t.Run(s, func(t *testing.T) {
			h, err := addr.ParseHost(s)
			require.NoError(t, err)
			require.Equal(t, addr.HostTypeIP, h.Type())
			assert.True(t, h.IP().Is6())
			assert.Equal(t, netip.MustParseAddr(s), h.IP())
		})
	}

	ipv4 := []string{
		"0.0.0.0",
		"127.0.0.1",
		"198.51.100.0",
		"198.51.100.1",
		"198.51.100.254",
		"198.51.100.255",
		"255.255.255.255",
	}
	for _, s := range ipv4 {
		t.Run(s, func(t *testing.T) {
			h, err := addr.ParseHost(s)
			require.NoError(t, err)
			require.Equal(t, addr.HostTypeIP, h.Type())
			assert.True(t, h.IP().Is4())
			assert.Equal(t, netip.MustParseAddr(s), h.IP())
		})
	}

	svcs := map[string]addr.SVC{
		"CS":         addr.SvcCS,
		"DS":         addr.SvcDS,
		"Wildcard":   addr.SvcWildcard,
		"CS_A":       addr.SvcCS,
		"DS_A":       addr.SvcDS,
		"Wildcard_A": addr.SvcWildcard,
		"CS_M":       addr.SvcCS.Multicast(),
		"DS_M":       addr.SvcDS.Multicast(),
		"Wildcard_M": addr.SvcWildcard.Multicast(),
	}
	for src, svc := range svcs {
		t.Run(src, func(t *testing.T) {
			h, err := addr.ParseHost(src)
			require.NoError(t, err)
			require.Equal(t, addr.HostTypeSVC, h.Type())
			assert.Equal(t, svc, h.SVC())
		})
	}
}
