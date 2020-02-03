// Copyright 2019 Anapaya Systems
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

package snet_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestUDPAddrInterface(t *testing.T) {
	var x interface{} = &snet.UDPAddr{}
	_, ok := x.(net.Addr)
	assert.True(t, ok, "should implement net interface")
}

func TestUDPAddrString(t *testing.T) {
	tests := map[string]struct {
		input *snet.UDPAddr
		want  string
	}{
		"empty": {
			input: &snet.UDPAddr{},
			want:  "0-0,<nil>",
		},
		"empty host": {
			input: &snet.UDPAddr{Host: &net.UDPAddr{}},
			want:  "0-0,:0",
		},
		"ipv4": {
			input: &snet.UDPAddr{
				IA:   xtest.MustParseIA("1-ff00:0:320"),
				Host: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 10000},
			},
			want: "1-ff00:0:320,1.2.3.4:10000",
		},
		"ipv6": {
			input: &snet.UDPAddr{
				IA:   xtest.MustParseIA("1-ff00:0:320"),
				Host: &net.UDPAddr{IP: net.ParseIP("2001::1"), Port: 20000},
			},
			want: "1-ff00:0:320,[2001::1]:20000",
		},
	}
	for n, tc := range tests {
		t.Run(n, func(t *testing.T) {
			a := tc.input.String()
			assert.Equal(t, a, tc.want)
		})
	}
}

func TestUDPAddrSet(t *testing.T) {
	testCases := map[string]struct {
		Input string
		Error assert.ErrorAssertionFunc
		Want  *snet.UDPAddr
	}{
		"empty string": {
			Input: "",
			Error: assert.Error,
		},
		"malformed IA": {
			Input: "1-ff000:0:0,192.168.1.1:80",
			Error: assert.Error,
		},
		"malformed IP": {
			Input: "1-ff00:0:1,192.1688.1.1:80",
			Error: assert.Error,
		},
		"malformed port": {
			Input: "1-ff00:0:1,192.168.1.1:123456",
			Error: assert.Error,
		},
		"bad symbol": {
			Input: "1-ff00:0:1x192.168.1.1:80",
			Error: assert.Error,
		},
		"good input": {
			Input: "1-ff00:0:1,192.168.1.1:80",
			Error: assert.NoError,
			Want: &snet.UDPAddr{
				IA: xtest.MustParseIA("1-ff00:0:1"),
				Host: &net.UDPAddr{
					IP:   net.ParseIP("192.168.1.1"),
					Port: 80,
				},
			},
		},
	}
	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {
			var a snet.UDPAddr
			err := a.Set(tc.Input)
			tc.Error(t, err)
			if err == nil {
				assert.Equal(t, tc.Want, &a)
			}
		})
	}
}

func TestUDPAddrFromString(t *testing.T) {
	tests := []struct {
		address string
		isError bool
		ia      string
		host    string
		port    int
	}{
		{address: "foo", isError: true},
		{address: "5-", isError: true},
		{address: "2-ff00:0:300,[", isError: true},
		{address: "5-ff00:0:300,[]:", isError: true},
		{address: "5-ff00:0:300,[127.0.0.1]:", isError: true},
		{address: "40-ff00:0:300,[]:19", isError: true},
		{address: "1-ff00:0:300,[]:13,[f", isError: true},
		{address: "1-ff00:0:300,[abc]:12", isError: true},
		{address: "1-ff00:0:300]:14,[1.2.3.4]", isError: true},
		{address: "1-ff00:0:300,[1.2.3.4]:70000", isError: true},
		{address: "1-ff00:0:300,[1.2.3.4]]", isError: true},
		{address: "1-ff00:0:300,::1:60000", isError: true},
		{address: "", isError: true},
		{address: "1-ff00:0:300,[1.2.3.4]:80",
			ia:   "1-ff00:0:300",
			host: "1.2.3.4",
			port: 80,
		},
		{address: "1-ff00:0:300,1.2.3.4:80",
			ia:   "1-ff00:0:300",
			host: "1.2.3.4",
			port: 80,
		},
		{address: "1-ff00:0:300,1.2.3.4:0",
			ia:   "1-ff00:0:300",
			host: "1.2.3.4",
			port: 0,
		},
		{address: "50-ff00:0:350,1.1.1.1:5",
			ia:   "50-ff00:0:350",
			host: "1.1.1.1",
			port: 5,
		},
		{address: "1-ff00:0:302,[::1]:60000",
			ia:   "1-ff00:0:302",
			host: "::1",
			port: 60000,
		},
		{address: "1-ff00:0:301,1.2.3.4",
			ia:   "1-ff00:0:301",
			host: "1.2.3.4",
			port: 0,
		},
		{address: "1-ff00:0:302,::1",
			ia:   "1-ff00:0:302",
			host: "::1",
			port: 0,
		},
		{address: "1-ff00:0:301,[1.2.3.4]",
			ia:   "1-ff00:0:301",
			host: "1.2.3.4",
			port: 0,
		},
		{address: "1-ff00:0:302,[::1]",
			ia:   "1-ff00:0:302",
			host: "::1",
			port: 0,
		},
	}
	for _, test := range tests {
		t.Log(fmt.Sprintf("given address %q", test.address))
		a, err := snet.UDPAddrFromString(test.address)
		if test.isError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.ia, a.IA.String())
			assert.Equal(t, net.ParseIP(test.host), a.Host.IP)
			assert.Equal(t, test.port, a.Host.Port)
		}
	}
}
