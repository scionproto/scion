// Copyright 2019 ETH Zurich
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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

func TestLocalMachineBuildAppAddress(t *testing.T) {
	tests := map[string]struct {
		Machine         *snet.LocalMachine
		ExpectedAppAddr *addr.AppAddr
	}{
		"nil IP": {
			Machine: &snet.LocalMachine{},
			ExpectedAppAddr: &addr.AppAddr{
				L3: addr.HostFromIP(nil),
			},
		},
		"only default IP": {
			Machine: &snet.LocalMachine{
				InterfaceIP: net.IP{192, 0, 2, 1},
			},
			ExpectedAppAddr: &addr.AppAddr{
				L3: addr.HostFromIP(net.IP{192, 0, 2, 1}),
			},
		},
		"if public IP is set, it is used to construct app address": {
			Machine: &snet.LocalMachine{
				InterfaceIP: net.IP{192, 168, 0, 1},
				PublicIP:    net.IP{192, 0, 2, 1},
			},
			ExpectedAppAddr: &addr.AppAddr{
				L3: addr.HostFromIP(net.IP{192, 0, 2, 1}),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.ExpectedAppAddr, test.Machine.AppAddress())
		})
	}
}

func TestLocalMachineBuildBindAddress(t *testing.T) {
	tests := map[string]struct {
		Machine          *snet.LocalMachine
		ExpectedBindAddr *net.UDPAddr
	}{
		"bind IP is computed based on default IP": {
			Machine: &snet.LocalMachine{
				InterfaceIP: net.IP{192, 0, 2, 1},
			},
			ExpectedBindAddr: &net.UDPAddr{IP: net.IP{192, 0, 2, 1}},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.ExpectedBindAddr, test.Machine.BindAddress())
		})
	}
}
