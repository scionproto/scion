// Copyright 2025 Anapaya Systems
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

package addrutil_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

func TestExtractServiceAddress(t *testing.T) {
	t.Run("valid Control Service with discovery info, returns no error and UDPAddr",
		func(t *testing.T) {
			ctrl := gomock.NewController(t)
			dummyIA := addr.MustParseIA("1-ff00:0:2")

			path := mock_snet.NewMockPath(ctrl)

			addrPort := netip.AddrPortFrom(netip.MustParseAddr("192.168.2.100"), 30652)
			discoveryInfo := make(map[addr.IA]snet.DiscoveryInformation)
			discoveryInfo[dummyIA] = snet.DiscoveryInformation{
				ControlServices: []netip.AddrPort{addrPort},
			}
			metadata := &snet.PathMetadata{
				Interfaces:           make([]snet.PathInterface, 1), // just non-empty
				DiscoveryInformation: discoveryInfo,
			}

			path.EXPECT().Metadata().Return(metadata)
			path.EXPECT().Dataplane().Return(snetpath.SCION{})
			path.EXPECT().Destination().Return(dummyIA)
			path.EXPECT().UnderlayNextHop().Return(
				&net.UDPAddr{IP: netip.MustParseAddr("10.1.1.1").AsSlice()},
			)

			want := &snet.UDPAddr{
				IA:      dummyIA,
				Path:    snetpath.SCION{},
				NextHop: &net.UDPAddr{IP: netip.MustParseAddr("10.1.1.1").AsSlice()},
				Host:    &net.UDPAddr{IP: netip.MustParseAddr("192.168.2.100").AsSlice(), Port: 30652},
			}

			retrievedAddr := addrutil.ExtractServiceAddress(addr.SvcCS, path)

			assert.Equal(t, want, retrievedAddr)
		})

	t.Run("valid Discovery Service with discovery info, returns no error and UDPAddr",
		func(t *testing.T) {
			ctrl := gomock.NewController(t)
			dummyIA := addr.MustParseIA("1-ff00:0:2")

			path := mock_snet.NewMockPath(ctrl)

			addrPort := netip.AddrPortFrom(netip.MustParseAddr("192.168.2.100"), 30652)
			discoveryInfo := make(map[addr.IA]snet.DiscoveryInformation)
			discoveryInfo[dummyIA] = snet.DiscoveryInformation{
				DiscoveryServices: []netip.AddrPort{addrPort},
			}
			metadata := &snet.PathMetadata{
				Interfaces:           make([]snet.PathInterface, 1), // just non-empty
				DiscoveryInformation: discoveryInfo,
			}

			path.EXPECT().Metadata().Return(metadata)
			path.EXPECT().Dataplane().Return(snetpath.SCION{})
			path.EXPECT().Destination().Return(dummyIA)
			path.EXPECT().UnderlayNextHop().Return(&net.UDPAddr{IP: netip.MustParseAddr("10.1.1.1").AsSlice()})

			want := &snet.UDPAddr{
				IA:      dummyIA,
				Path:    snetpath.SCION{},
				NextHop: &net.UDPAddr{IP: netip.MustParseAddr("10.1.1.1").AsSlice()},
				Host:    &net.UDPAddr{IP: netip.MustParseAddr("192.168.2.100").AsSlice(), Port: 30652},
			}

			retrievedAddr := addrutil.ExtractServiceAddress(addr.SvcDS, path)

			assert.Equal(t, want, retrievedAddr)
		})
}
