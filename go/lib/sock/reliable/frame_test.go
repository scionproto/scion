// Copyright 2018 ETH Zurich
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

package reliable

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/xtest"
)

func TestUnderlayPacketSerializeTo(t *testing.T) {
	type TestCase struct {
		Name          string
		Packet        *UnderlayPacket
		ExpectedData  []byte
		ExpectedError error
	}
	testCases := []TestCase{
		{
			Name:         "none type address, no data",
			Packet:       &UnderlayPacket{},
			ExpectedData: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 0},
		},
		{
			Name: "empty IP address",
			Packet: &UnderlayPacket{
				Address: &net.UDPAddr{},
			},
			ExpectedError: ErrNoAddress,
			ExpectedData:  []byte{},
		},
		{
			Name: "IPv4 host, with address, no port, no data",
			Packet: &UnderlayPacket{
				Address: &net.UDPAddr{IP: net.ParseIP("1.2.3.4")},
			},
			ExpectedError: ErrNoPort,
			ExpectedData:  []byte{},
		},
		{
			Name: "IPv4 host, with address, with port, no data",
			Packet: &UnderlayPacket{
				Address: &net.UDPAddr{IP: net.ParseIP("10.2.3.4"), Port: 80},
			},
			ExpectedData: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 0,
				10, 2, 3, 4, 0, 80},
		},
		{
			Name: "IPv6 host, with address, with port, no data",
			Packet: &UnderlayPacket{
				Address: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80},
			},
			ExpectedData: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 0,
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				0, 80},
		},
		{
			Name: "IPv4 host, with address, big port, no data",
			Packet: &UnderlayPacket{
				Address: &net.UDPAddr{IP: net.ParseIP("10.2.3.4"), Port: 0x1234},
			},
			ExpectedData: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 0,
				10, 2, 3, 4, 0x12, 0x34},
		},
		{
			Name: "long payload",
			Packet: &UnderlayPacket{
				Address: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 80},
				Payload: make([]byte, 2000),
			},
			ExpectedError: ErrBufferTooSmall,
			ExpectedData:  []byte{},
		},
		{
			Name: "good payload",
			Packet: &UnderlayPacket{
				Address: &net.UDPAddr{IP: net.ParseIP("10.2.3.4"), Port: 80},
				Payload: []byte{10, 5, 6, 7},
			},
			ExpectedData: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 4,
				10, 2, 3, 4, 0, 80, 10, 5, 6, 7},
		},
	}
	t.Run("Different packets serialize correctly", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.Name, func(t *testing.T) {
				b := make([]byte, 1500)
				n, err := tc.Packet.SerializeTo(b)
				xtest.AssertErrorsIs(t, err, tc.ExpectedError)
				assert.Equal(t, tc.ExpectedData, b[:n])
			})
		}
	})
}

func TestUnderlayPacketDecodeFromBytes(t *testing.T) {
	type TestCase struct {
		Name           string
		Buffer         []byte
		ExpectedPacket UnderlayPacket
		ExpectedError  error
	}
	testCases := []TestCase{
		{
			Name:          "incomplete header",
			Buffer:        []byte{0xaa},
			ExpectedError: ErrIncompleteFrameHeader,
		},
		{
			Name:          "bad cookie",
			Buffer:        []byte{0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0, 0, 0, 0, 0},
			ExpectedError: ErrBadCookie,
		},
		{
			Name:          "bad address type",
			Buffer:        []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 3, 0, 0, 0, 0},
			ExpectedError: ErrBadAddressType,
		},
		{
			Name: "incomplete address",
			Buffer: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 0,
				10, 2, 3},
			ExpectedError: ErrIncompleteAddress,
		},
		{
			Name: "incomplete port",
			Buffer: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 0,
				10, 2, 3, 4, 0},
			ExpectedError: ErrIncompletePort,
		},
		{
			Name: "bad length (underflow)",
			Buffer: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 0,
				10, 2, 3, 4, 0, 80, 42},
			ExpectedError: ErrBadLength,
		},
		{
			Name: "bad length (overflow)",
			Buffer: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 2,
				10, 2, 3, 4, 0, 80, 42},
			ExpectedError: ErrBadLength,
		},
		{
			Name:   "good packet (none type address)",
			Buffer: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 1, 42},
			ExpectedPacket: UnderlayPacket{
				Payload: []byte{42},
			},
		},
		{
			Name: "good packet (IPv4)",
			Buffer: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 1,
				10, 2, 3, 4, 0, 80, 42},
			ExpectedPacket: UnderlayPacket{
				Address: &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 80},
				Payload: []byte{42},
			},
		},
		{
			Name: "good packet (IPv6)",
			Buffer: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 1,
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				0, 80, 42},
			ExpectedPacket: UnderlayPacket{
				Address: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80},
				Payload: []byte{42},
			},
		},
	}
	t.Run("Different packets decode correctly", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.Name, func(t *testing.T) {
				var p UnderlayPacket
				err := p.DecodeFromBytes(tc.Buffer)
				xtest.AssertErrorsIs(t, err, tc.ExpectedError)
				assert.Equal(t, tc.ExpectedPacket, p)
			})
		}
	})
}
