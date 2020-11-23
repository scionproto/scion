// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dataplane_test

import (
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/mocks/io/mock_io"
	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/control"
	"github.com/scionproto/scion/go/pkg/gateway/control/mock_control"
	"github.com/scionproto/scion/go/pkg/gateway/dataplane"
)

func TestIPReader(t *testing.T) {
	t.Run("nil routing table", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ipForwarder := &dataplane.IPForwarder{
			Reader: mock_io.NewMockReader(ctrl),
		}
		err := ipForwarder.Run()
		assert.Error(t, err)
	})

	t.Run("nil packet reader", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ipForwarder := &dataplane.IPForwarder{
			RoutingTable: mock_control.NewMockRoutingTable(ctrl),
		}
		err := ipForwarder.Run()
		assert.Error(t, err)
	})

	t.Run("successful run", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		reader := mock_io.NewMockReader(ctrl)
		rt := dataplane.NewRoutingTable(nil, []*control.RoutingChain{
			{
				Prefixes:        []*net.IPNet{xtest.MustParseCIDR(t, "10.0.0.0/8")},
				TrafficMatchers: []control.TrafficMatcher{{ID: 1, Matcher: pktcls.CondTrue}},
			},
			{
				Prefixes:        []*net.IPNet{xtest.MustParseCIDR(t, "::1/128")},
				TrafficMatchers: []control.TrafficMatcher{{ID: 2, Matcher: pktcls.CondTrue}},
			},
		})
		art := &dataplane.AtomicRoutingTable{}
		art.SetRoutingTable(rt)

		sessionOne := mock_control.NewMockPktWriter(ctrl)
		rt.AddRoute(
			1,
			sessionOne,
		)

		sessionTwo := mock_control.NewMockPktWriter(ctrl)
		rt.AddRoute(
			2,
			sessionTwo,
		)

		ipv4Packet := newIPv4Packet(t, net.IP{10, 0, 0, 1})
		reader.EXPECT().Read(gomock.Any()).DoAndReturn(
			func(b []byte) (int, error) { return copy(b, ipv4Packet), nil },
		)
		sessionOne.EXPECT().Write(ipv4Packet)

		brokenPacket := []byte{1, 3, 3, 7}
		reader.EXPECT().Read(gomock.Any()).DoAndReturn(
			func(b []byte) (int, error) { return copy(b, brokenPacket), nil },
		)

		zeroLengthPacket := []byte{}
		reader.EXPECT().Read(gomock.Any()).DoAndReturn(
			func(b []byte) (int, error) { return copy(b, zeroLengthPacket), nil },
		)

		ipv6Packet := newIPv6Packet(t, net.IPv6loopback)
		reader.EXPECT().Read(gomock.Any()).DoAndReturn(
			func(b []byte) (int, error) { return copy(b, ipv6Packet), nil },
		)
		sessionTwo.EXPECT().Write(ipv6Packet)

		done := make(chan struct{})
		// Block reader forever so it doesn't busy loop reading nothing.
		reader.EXPECT().Read(gomock.Any()).DoAndReturn(
			func(b []byte) (int, error) { close(done); select {} },
		)

		ipForwarder := &dataplane.IPForwarder{
			Reader:       reader,
			RoutingTable: art,
		}

		go func() {
			err := ipForwarder.Run()
			require.NoError(t, err)
		}()

		xtest.AssertReadReturnsBefore(t, done, time.Second)
	})
}

func newIPv4Packet(t *testing.T, destination net.IP) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts,
		&layers.IPv4{
			Version: 4,
			Length:  20, // only header
			IHL:     5,  // 20 bytes header
			SrcIP:   net.IP{127, 0, 0, 1},
			DstIP:   destination,
		},
	)
	require.NoError(t, err)
	return buf.Bytes()
}

func newIPv6Packet(t *testing.T, destination net.IP) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts,
		&layers.IPv6{
			Version:    6,
			Length:     8,
			SrcIP:      net.IPv6loopback,
			DstIP:      destination,
			NextHeader: layers.IPProtocolUDP,
		},
		&layers.UDP{},
	)
	require.NoError(t, err)
	return buf.Bytes()
}
