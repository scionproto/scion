// Copyright 2020 Anapaya Systems
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

package dataplane_test

import (
	"bytes"
	"errors"
	"fmt"
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
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/control"
	"github.com/scionproto/scion/go/pkg/gateway/control/mock_control"
	"github.com/scionproto/scion/go/pkg/gateway/dataplane"
)

func TestIPForwarderRun(t *testing.T) {
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

	t.Run("fragmented packets", func(t *testing.T) {
		testCases := map[string]struct {
			input func(*testing.T) gopacket.Packet
		}{
			"ipv4 middle fragment": {
				input: func(t *testing.T) gopacket.Packet {
					buf, opts := gopacket.NewSerializeBuffer(), gopacket.SerializeOptions{}
					err := gopacket.SerializeLayers(buf, opts,
						&layers.IPv4{
							Version: 4,
							TTL:     20,
							IHL:     5,
							Length:  20,
							SrcIP:   net.IPv4(1, 1, 1, 1),
							DstIP:   net.IPv4(2, 2, 2, 2),
							Flags:   layers.IPv4MoreFragments,
						},
					)
					require.NoError(t, err)
					return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4,
						gopacket.DecodeOptions{NoCopy: true, Lazy: true})
				},
			},
			"ipv4 last fragment": {
				input: func(t *testing.T) gopacket.Packet {
					buf, opts := gopacket.NewSerializeBuffer(), gopacket.SerializeOptions{}
					err := gopacket.SerializeLayers(buf, opts,
						&layers.IPv4{
							Version:    4,
							TTL:        20,
							IHL:        5,
							Length:     20,
							SrcIP:      net.IPv4(1, 1, 1, 1),
							DstIP:      net.IPv4(2, 2, 2, 2),
							FragOffset: 64,
						},
					)
					require.NoError(t, err)
					return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4,
						gopacket.DecodeOptions{NoCopy: true, Lazy: true})
				},
			},
		}

		for name, tc := range testCases {
			name, tc := name, tc
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				reader := mock_io.NewMockReader(ctrl)

				ipForwarder := &dataplane.IPForwarder{
					Reader:       reader,
					RoutingTable: mock_control.NewMockRoutingTable(ctrl),
				}

				reader.EXPECT().Read(gomock.Any()).DoAndReturn(
					func(b []byte) (int, error) {
						return copy(b, tc.input(t).Data()), nil
					},
				)

				// Force IP forwarder to shut down.
				errDone := serrors.New("done")
				reader.EXPECT().Read(gomock.Any()).Return(0, errDone)

				done := make(chan struct{})
				go func() {
					err := ipForwarder.Run()
					require.True(t, errors.Is(err, errDone), err)
					close(done)
				}()

				xtest.AssertReadReturnsBefore(t, done, time.Second)
			})
		}
	})

	t.Run("successful run", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		reader := mock_io.NewMockReader(ctrl)
		rt := dataplane.NewRoutingTable([]*control.RoutingChain{
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
		rt.SetSession(
			1,
			sessionOne,
		)

		sessionTwo := mock_control.NewMockPktWriter(ctrl)
		rt.SetSession(
			2,
			sessionTwo,
		)

		ipv4Packet := newIPv4Packet(t, net.IP{10, 0, 0, 1})
		reader.EXPECT().Read(gomock.Any()).DoAndReturn(
			func(b []byte) (int, error) {
				return copy(b, ipv4Packet.Data()), nil
			},
		)
		sessionOne.EXPECT().Write(Packet(ipv4Packet))

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
			func(b []byte) (int, error) { return copy(b, ipv6Packet.Data()), nil },
		)
		sessionTwo.EXPECT().Write(Packet(ipv6Packet))

		// Force IP forwarder to shut down.
		errDone := serrors.New("done")
		reader.EXPECT().Read(gomock.Any()).Return(0, errDone)

		ipForwarder := &dataplane.IPForwarder{
			Reader:       reader,
			RoutingTable: art,
		}

		done := make(chan struct{})
		go func() {
			err := ipForwarder.Run()
			require.True(t, errors.Is(err, errDone), err)
			close(done)
		}()

		xtest.AssertReadReturnsBefore(t, done, time.Second)
	})
}

func newIPv4Packet(t *testing.T, destination net.IP) gopacket.Packet {
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

	decodeOptions := gopacket.DecodeOptions{
		NoCopy: true,
		Lazy:   true,
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, decodeOptions)
}

func newIPv6Packet(t *testing.T, destination net.IP) gopacket.Packet {
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

	decodeOptions := gopacket.DecodeOptions{
		NoCopy: true,
		Lazy:   true,
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv6, decodeOptions)
}

type packetMatcher struct {
	packet gopacket.Packet
}

func (pm *packetMatcher) Matches(x interface{}) bool {
	packet := x.(gopacket.Packet)
	return bytes.Compare(packet.Data(), pm.packet.Data()) == 0
}

func (pm *packetMatcher) String() string {
	return fmt.Sprintf("%v", pm.packet.Data())
}

// Packet returns a matcher that compares packets based on their data.
func Packet(pkt gopacket.Packet) gomock.Matcher { return &packetMatcher{pkt} }
