// Copyright 2017 ETH Zurich
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

package topology

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	pubIPv4    = &RawAddrPortOverlay{RawAddrPort{"192.168.1.1", 40000}, 0}
	pubUDPIPv4 = &RawAddrPortOverlay{RawAddrPort{"192.168.1.1", 40001}, 30041}
	bindIPv4   = &RawAddrPort{"127.0.0.1", 40002}
	pubIPv6    = &RawAddrPortOverlay{RawAddrPort{"2001:db8:a0b:12f0::1", 60000}, 0}
	pubUDPIPv6 = &RawAddrPortOverlay{RawAddrPort{"2001:db8:a0b:12f0::1", 60001}, 30041}
	bindIPv6   = &RawAddrPort{"::1", 60002}
	pubBad     = &RawAddrPortOverlay{RawAddrPort{"BadIPAddress", 40000}, 0}
	bindBad    = &RawAddrPort{"BadIPAddress", 40000}
)

func TestRawAddrMap_ToTopoAddr(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		ram  RawAddrMap
		addr *TopoAddr
	}{
		{
			name: "No addresses",
			err:  ErrAtLeastOnePub,
			ram:  make(RawAddrMap),
			addr: nil,
		},
		{
			name: "IPv4 invalid address",
			err:  ErrInvalidPub,
			ram: RawAddrMap{
				"IPv4": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "foo",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv4 empty address",
			err:  ErrInvalidPub,
			ram: RawAddrMap{
				"IPv4": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv6 address in IPv4 property",
			err:  ErrInvalidPub,
			ram: RawAddrMap{
				"IPv4": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "2001:db8:f00:b43::1",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv4 address in IPv6 property",
			err:  ErrInvalidPub,
			ram: RawAddrMap{
				"IPv6": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "192.168.1.1",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv6 invalid address",
			err:  ErrInvalidPub,
			ram: RawAddrMap{
				"IPv6": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "foo",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv6 empty address",
			err:  ErrInvalidPub,
			ram: RawAddrMap{
				"IPv6": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv4 good address",
			ram: RawAddrMap{
				"IPv4": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "192.168.1.1",
							L4Port: 42,
						},
					},
				},
			},
			addr: &TopoAddr{
				SCIONAddress: &addr.AppAddr{
					L3: addr.HostFromIP(net.IP{192, 168, 1, 1}),
					L4: 42,
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.IP{192, 168, 1, 1},
					Port: 30041,
				},
			},
		},
		{
			name: "IPv6 good address",
			ram: RawAddrMap{
				"IPv6": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "2001:db8:f00:b43::1",
							L4Port: 42,
						},
					},
				},
			},
			addr: &TopoAddr{
				SCIONAddress: &addr.AppAddr{
					L3: addr.HostFromIP(net.ParseIP("2001:db8:f00:b43::1")),
					L4: 42,
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:f00:b43::1"),
					Port: 30041,
				},
			},
		},
		{
			name: "IPv4 with bind",
			err:  ErrBindNotSupported,
			ram: RawAddrMap{
				"IPv4": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "192.168.1.1",
							L4Port: 42,
						},
					},
					Bind: &RawAddrPort{},
				},
			},
			addr: nil,
		},
		{
			name: "IPv6 with bind",
			err:  ErrBindNotSupported,
			ram: RawAddrMap{
				"IPv6": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "2001:db8:f00:b43::1",
							L4Port: 42,
						},
					},
					Bind: &RawAddrPort{},
				},
			},
			addr: nil,
		},
		{
			name: "IPv4 with custom underlay",
			err:  ErrCustomUnderlayPortNotSupported,
			ram: RawAddrMap{
				"IPv4": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "192.168.1.1",
							L4Port: 42,
						},
						OverlayPort: 73,
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv6 with custom underlay",
			err:  ErrCustomUnderlayPortNotSupported,
			ram: RawAddrMap{
				"IPv6": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "2001:db8:f00:b43::1",
							L4Port: 42,
						},
						OverlayPort: 73,
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv4 with IPv6",
			ram: RawAddrMap{
				"IPv4": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "192.168.1.1",
							L4Port: 42,
						},
					},
				},
				"IPv6": &RawPubBindOverlay{
					Public: RawAddrPortOverlay{
						RawAddrPort: RawAddrPort{
							Addr:   "2001:db8:f00:b43::1",
							L4Port: 42,
						},
					},
				},
			},
			addr: &TopoAddr{
				SCIONAddress: &addr.AppAddr{
					L3: addr.HostFromIP(net.ParseIP("2001:db8:f00:b43::1")),
					L4: 42,
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:f00:b43::1"),
					Port: 30041,
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			topoAddr, err := tc.ram.ToTopoAddr()
			xtest.AssertErrorsIs(t, err, tc.err)
			if tc.err == nil {
				assert.Equal(t, tc.addr, topoAddr)
			}
		})
	}
}
