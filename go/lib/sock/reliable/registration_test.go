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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestRegistrationMessageSerializeTo(t *testing.T) {
	type TestCase struct {
		Name          string
		Registration  *Registration
		ExpectedError string
		ExpectedData  []byte
	}
	testCases := []TestCase{
		{
			Name: "nil public address",
			Registration: &Registration{
				IA:         xtest.MustParseIA("1-ff00:0:1"),
				SVCAddress: addr.SvcNone,
			},
			ExpectedData:  []byte{},
			ExpectedError: ErrNoAddress,
		},
		{
			Name: "nil public address IP",
			Registration: &Registration{
				IA:            xtest.MustParseIA("1-ff00:0:1"),
				PublicAddress: &net.UDPAddr{Port: 80},
				SVCAddress:    addr.SvcNone,
			},
			ExpectedData:  []byte{},
			ExpectedError: ErrNoAddress,
		},
		{
			Name: "public IPv4 address only",
			Registration: &Registration{
				IA:            xtest.MustParseIA("1-ff00:0:1"),
				PublicAddress: &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 80},
				SVCAddress:    addr.SvcNone,
			},
			ExpectedData: []byte{0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01, 0, 80, 1,
				10, 2, 3, 4},
		},
		{
			Name: "public IPv6 address only",
			Registration: &Registration{
				IA:            xtest.MustParseIA("1-ff00:0:1"),
				PublicAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80},
				SVCAddress:    addr.SvcNone,
			},
			ExpectedData: []byte{0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 2, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			Name: "public address with bind",
			Registration: &Registration{
				IA:            xtest.MustParseIA("1-ff00:0:1"),
				PublicAddress: &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 80},
				BindAddress:   &net.UDPAddr{IP: net.IP{10, 5, 6, 7}, Port: 81},
				SVCAddress:    addr.SvcNone,
			},
			ExpectedData: []byte{0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 1, 10, 2, 3, 4, 0, 81, 1, 10, 5, 6, 7},
		},
		{
			Name: "public IPv4 address with SVC",
			Registration: &Registration{
				IA:            xtest.MustParseIA("1-ff00:0:1"),
				PublicAddress: &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 80},
				SVCAddress:    addr.SvcPS,
			},
			ExpectedData: []byte{0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01, 0,
				80, 1, 10, 2, 3, 4, 0x00, 0x01},
		},
		{
			Name: "public address with bind and SVC",
			Registration: &Registration{
				IA:            xtest.MustParseIA("1-ff00:0:1"),
				PublicAddress: &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 80},
				BindAddress:   &net.UDPAddr{IP: net.IP{10, 5, 6, 7}, Port: 81},
				SVCAddress:    addr.SvcCS,
			},
			ExpectedData: []byte{0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 1, 10, 2, 3, 4,
				0, 81, 1, 10, 5, 6, 7, 0, 2},
		},
	}
	Convey("", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				b := make([]byte, 1500)
				n, err := tc.Registration.SerializeTo(b)
				xtest.SoMsgErrorStr("err", err, tc.ExpectedError)
				SoMsg("data", b[:n], ShouldResemble, tc.ExpectedData)
			})
		}
	})
}

func TestRegistrationMessageDecodeFromBytes(t *testing.T) {
	type TestCase struct {
		Name                 string
		Data                 []byte
		ExpectedError        string
		ExpectedRegistration Registration
	}
	testCases := []TestCase{
		{
			Name:          "incomplete message",
			Data:          []byte{0x03, 17, 0, 1},
			ExpectedError: ErrIncompleteMessage,
		},
		{
			Name: "incomplete address",
			Data: []byte{0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 1, 10, 0, 0},
			ExpectedError: ErrIncompleteAddress,
		},
		{
			Name: "bad address type",
			Data: []byte{0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 9, 10, 2, 3, 4},
			ExpectedError: ErrBadAddressType,
		},
		{
			Name: "public IPv4 address only",
			Data: []byte{0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 1, 10, 2, 3, 4},
			ExpectedRegistration: Registration{
				IA:            xtest.MustParseIA("1-ff00:0:1"),
				PublicAddress: &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 80},
				SVCAddress:    addr.SvcNone,
			},
		},
		{
			Name: "public IPv6 address only",
			Data: []byte{0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 2, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			ExpectedRegistration: Registration{
				IA:            xtest.MustParseIA("1-ff00:0:1"),
				PublicAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80},
				SVCAddress:    addr.SvcNone,
			},
		},
		{
			Name: "public address with bind",
			Data: []byte{0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 1, 10, 2, 3, 4,
				0, 81, 1, 10, 5, 6, 7},
			ExpectedRegistration: Registration{
				IA:            xtest.MustParseIA("1-ff00:0:1"),
				PublicAddress: &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 80},
				BindAddress:   &net.UDPAddr{IP: net.IP{10, 5, 6, 7}, Port: 81},
				SVCAddress:    addr.SvcNone,
			},
		},
		{
			Name: "incomplete bind starting information",
			Data: []byte{0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 1, 10, 2, 3, 4,
				0, 81},
			ExpectedError: ErrIncompleteMessage,
		},
		{
			Name: "incomplete bind address",
			Data: []byte{0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 1, 10, 2, 3, 4,
				0, 81, 1, 10, 0, 0},
			ExpectedError: ErrIncompleteAddress,
		},
		{
			Name: "bad bind address type",
			Data: []byte{0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 1, 10, 0, 0, 1,
				0, 81, 9, 10, 0, 0, 2},
			ExpectedError: ErrBadAddressType,
		},
		{
			Name: "public IPv6 address with bind",
			Data: []byte{0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 2, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				0, 81, 2, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
			},
			ExpectedRegistration: Registration{
				IA:            xtest.MustParseIA("1-ff00:0:1"),
				PublicAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80},
				BindAddress:   &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 81},
				SVCAddress:    addr.SvcNone,
			},
		},
		{
			Name: "excess of 1 byte is error",
			Data: []byte{0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 1, 10, 2, 3, 4,
				0, 81, 1, 10, 5, 6, 7,
				42},
			ExpectedError: ErrPayloadTooLong,
		},
		{
			Name: "excess of 3 bytes (or more) is error",
			Data: []byte{0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 1, 10, 2, 3, 4,
				0, 81, 1, 10, 5, 6, 7,
				42, 42, 42},
			ExpectedError: ErrPayloadTooLong,
		},
		{
			Name: "excess of 2 bytes is SVC address",
			Data: []byte{0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01,
				0, 80, 1, 10, 2, 3, 4,
				0, 81, 1, 10, 5, 6, 7,
				0x00, 0x01},
			ExpectedRegistration: Registration{
				IA:            xtest.MustParseIA("1-ff00:0:1"),
				PublicAddress: &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 80},
				BindAddress:   &net.UDPAddr{IP: net.IP{10, 5, 6, 7}, Port: 81},
				SVCAddress:    addr.SvcPS,
			},
		},
	}
	Convey("", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				var r Registration
				err := r.DecodeFromBytes(tc.Data)
				xtest.SoMsgErrorStr("err", err, tc.ExpectedError)
				SoMsg("registration", r, ShouldResemble, tc.ExpectedRegistration)
			})
		}
	})
}

func TestConfirmationMessageSerializeTo(t *testing.T) {
	Convey("", t, func() {
		confirmation := &Confirmation{Port: 0xaabb}
		Convey("bad buffer", func() {
			b := make([]byte, 1)
			n, err := confirmation.SerializeTo(b)
			xtest.SoMsgErrorStr("err", err, ErrBufferTooSmall)
			SoMsg("n", n, ShouldEqual, 0)
		})
		Convey("success", func() {
			b := make([]byte, 1500)
			n, err := confirmation.SerializeTo(b)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("data", b[:n], ShouldResemble, []byte{0xaa, 0xbb})
		})
	})
}

func TestConfirmationDecodeFromBytes(t *testing.T) {
	Convey("", t, func() {
		var confirmation Confirmation
		Convey("bad buffer", func() {
			b := []byte{0xaa}
			err := confirmation.DecodeFromBytes(b)
			xtest.SoMsgErrorStr("err", err, ErrIncompletePort)
			SoMsg("data", confirmation, ShouldResemble, Confirmation{})
		})
		Convey("success", func() {
			b := []byte{0xaa, 0xbb}
			err := confirmation.DecodeFromBytes(b)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("data", confirmation, ShouldResemble, Confirmation{Port: 0xaabb})
		})
	})
}
