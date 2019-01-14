// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package main

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/xtest"
)

const (
	dispatcherTestPort  uint16 = 40031
	defaultTimeout             = 2 * time.Second
	defaultWaitDuration        = 200 * time.Millisecond
)

type TestSettings struct {
	ApplicationSocket string
	OverlayPort       int
}

func InitTestSettings(t *testing.T) TestSettings {
	ringbuf.InitMetrics("dispatcher", nil)
	socketName, err := getSocketName("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	return &TestSettings{
		ApplicationSocket: socketName,
		OverlayPort:       int(dispatcherTestPort),
	}
}

func getSocketName(dir string) (string, error) {
	dir, err := ioutil.TempDir(dir, "dispatcher")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "server.sock"), nil
}

type ClientAddress struct {
	IA             addr.IA
	PublicAddress  addr.HostAddr
	PublicPort     addr.L4Info
	ServiceAddress addr.HostSVC
	OverlayAddress addr.HostAddr
	OverlayPort    addr.L4Info
}

// Addressing information
var (
	commonIA               = xtest.MustParseIA("1-ff00:0:1")
	commonPublicL3Address  = addr.HostFromIP(net.IP{127, 0, 0, 1})
	commonOverlayL3Address = addr.HostFromIP(net.IP{127, 0, 0, 1})
	commonOverlayL4Address = addr.NewL4UDPInfo(dispatcherTestPort)
	clientXAddress         = &ClientAddress{
		IA:             commonIA,
		PublicAddress:  commonPublicL3Address,
		PublicPort:     addr.NewL4UDPInfo(8080),
		ServiceAddress: addr.SvcNone,
		OverlayAddress: commonOverlayL3Address,
		OverlayPort:    commonOverlayL4Address,
	}
	clientYAddress = &ClientAddress{
		IA:             commonIA,
		PublicAddress:  commonPublicL3Address,
		PublicPort:     addr.NewL4UDPInfo(8081),
		ServiceAddress: addr.SvcPS,
		OverlayAddress: commonOverlayL3Address,
		OverlayPort:    commonOverlayL4Address,
	}
)

type TestCase struct {
	Name           string
	ClientAddress  *ClientAddress
	TestPacket     *spkt.ScnPkt
	OverlayAddress *overlay.OverlayAddr
	ExpectedPacket *spkt.ScnPkt
}

var testCases = []*TestCase{
	{
		Name:          "UDP/IPv4 packet",
		ClientAddress: clientXAddress,
		TestPacket: &spkt.ScnPkt{
			SrcIA:   clientXAddress.IA,
			DstIA:   clientXAddress.IA,
			SrcHost: clientXAddress.PublicAddress,
			DstHost: clientXAddress.PublicAddress,
			L4: &l4.UDP{
				SrcPort: clientXAddress.PublicPort.Port(),
				DstPort: clientXAddress.PublicPort.Port(),
			},
			Pld: common.RawBytes{1, 2, 3, 4},
		},
		OverlayAddress: MustNewOverlayAddr(
			clientXAddress.OverlayAddress,
			clientXAddress.OverlayPort,
		),
		ExpectedPacket: &spkt.ScnPkt{
			SrcIA:   clientXAddress.IA,
			DstIA:   clientXAddress.IA,
			SrcHost: clientXAddress.PublicAddress,
			DstHost: clientXAddress.PublicAddress,
			L4: &l4.UDP{
				SrcPort:  clientXAddress.PublicPort.Port(),
				DstPort:  clientXAddress.PublicPort.Port(),
				TotalLen: 12,
				Checksum: common.RawBytes{0xc0, 0xb3},
			},
			Pld: common.RawBytes{1, 2, 3, 4},
		},
	},
	{
		Name:          "UDP/SVC packet",
		ClientAddress: clientYAddress,
		TestPacket: &spkt.ScnPkt{
			SrcIA:   clientYAddress.IA,
			DstIA:   clientYAddress.IA,
			SrcHost: clientYAddress.PublicAddress,
			DstHost: clientYAddress.ServiceAddress,
			L4: &l4.UDP{
				SrcPort: clientYAddress.PublicPort.Port(),
				DstPort: clientYAddress.PublicPort.Port(),
			},
			Pld: common.RawBytes{5, 6, 7, 8},
		},
		OverlayAddress: MustNewOverlayAddr(
			clientXAddress.OverlayAddress,
			clientXAddress.OverlayPort,
		),
		ExpectedPacket: &spkt.ScnPkt{
			SrcIA:   clientYAddress.IA,
			DstIA:   clientYAddress.IA,
			SrcHost: clientYAddress.PublicAddress,
			DstHost: clientYAddress.ServiceAddress,
			L4: &l4.UDP{
				SrcPort:  clientYAddress.PublicPort.Port(),
				DstPort:  clientYAddress.PublicPort.Port(),
				TotalLen: 12,
				Checksum: common.RawBytes{0x37, 0xaa},
			},
			Pld: common.RawBytes{5, 6, 7, 8},
		},
	},
	{
		Name:          "SCMP::General::EchoRequest",
		ClientAddress: clientXAddress,
		OverlayAddress: MustNewOverlayAddr(
			clientXAddress.OverlayAddress,
			clientXAddress.OverlayPort,
		),
		TestPacket: &spkt.ScnPkt{
			SrcIA:   clientXAddress.IA,
			DstIA:   clientYAddress.IA,
			SrcHost: clientXAddress.PublicAddress,
			DstHost: clientYAddress.PublicAddress,
			L4: &scmp.Hdr{
				Class: scmp.C_General, Type: scmp.T_G_EchoRequest,
			},
			Pld: &scmp.Payload{
				Meta: &scmp.Meta{InfoLen: uint8((&scmp.InfoEcho{}).Len())},
				Info: &scmp.InfoEcho{Id: 0xdeadbeef},
			},
		},
		ExpectedPacket: &spkt.ScnPkt{
			SrcIA:   clientYAddress.IA,
			DstIA:   clientXAddress.IA,
			SrcHost: clientYAddress.PublicAddress,
			DstHost: clientXAddress.PublicAddress,
			L4: &scmp.Hdr{
				Class: scmp.C_General, Type: scmp.T_G_EchoReply,
				TotalLen: 40,
				Checksum: common.RawBytes{0x56, 0x2e},
			},
			Pld: &scmp.Payload{
				Meta: &scmp.Meta{
					InfoLen: uint8((&scmp.InfoEcho{}).Len()),
				},
				Info:    &scmp.InfoEcho{Id: 0xdeadbeef},
				CmnHdr:  common.RawBytes{},
				AddrHdr: common.RawBytes{},
				PathHdr: common.RawBytes{},
				ExtHdrs: common.RawBytes{},
				L4Hdr:   common.RawBytes{},
			},
		},
	},
	{
		Name:          "SCMP::General::TraceRouteRequest",
		ClientAddress: clientXAddress,
		OverlayAddress: MustNewOverlayAddr(
			clientXAddress.OverlayAddress,
			clientXAddress.OverlayPort,
		),
		TestPacket: &spkt.ScnPkt{
			SrcIA:   clientXAddress.IA,
			DstIA:   clientYAddress.IA,
			SrcHost: clientXAddress.PublicAddress,
			DstHost: clientYAddress.PublicAddress,
			L4: &scmp.Hdr{
				Class: scmp.C_General, Type: scmp.T_G_TraceRouteRequest,
			},
			Pld: &scmp.Payload{
				Meta: &scmp.Meta{InfoLen: uint8((&scmp.InfoTraceRoute{}).Len())},
				Info: &scmp.InfoTraceRoute{Id: 0xcafecafe},
			},
		},
		ExpectedPacket: &spkt.ScnPkt{
			SrcIA:   clientYAddress.IA,
			DstIA:   clientXAddress.IA,
			SrcHost: clientYAddress.PublicAddress,
			DstHost: clientXAddress.PublicAddress,
			L4: &scmp.Hdr{
				Class: scmp.C_General, Type: scmp.T_G_TraceRouteReply,
				TotalLen: 56,
				Checksum: common.RawBytes{0x4d, 0xbc},
			},
			Pld: &scmp.Payload{
				Meta: &scmp.Meta{
					InfoLen: uint8((&scmp.InfoTraceRoute{}).Len()),
				},
				Info:    &scmp.InfoTraceRoute{Id: 0xcafecafe},
				CmnHdr:  common.RawBytes{},
				AddrHdr: common.RawBytes{},
				PathHdr: common.RawBytes{},
				ExtHdrs: common.RawBytes{},
				L4Hdr:   common.RawBytes{},
			},
		},
	},
	{
		Name:          "SCMP::General::RecordPathRequest",
		ClientAddress: clientXAddress,
		OverlayAddress: MustNewOverlayAddr(
			clientXAddress.OverlayAddress,
			clientXAddress.OverlayPort,
		),
		TestPacket: &spkt.ScnPkt{
			SrcIA:   clientXAddress.IA,
			DstIA:   clientYAddress.IA,
			SrcHost: clientXAddress.PublicAddress,
			DstHost: clientYAddress.PublicAddress,
			L4: &scmp.Hdr{
				Class: scmp.C_General, Type: scmp.T_G_RecordPathRequest,
			},
			Pld: &scmp.Payload{
				Meta: &scmp.Meta{InfoLen: uint8((&scmp.InfoRecordPath{}).Len())},
				Info: &scmp.InfoRecordPath{Id: 0xf00dcafe},
			},
		},
		ExpectedPacket: &spkt.ScnPkt{
			SrcIA:   clientYAddress.IA,
			DstIA:   clientXAddress.IA,
			SrcHost: clientYAddress.PublicAddress,
			DstHost: clientXAddress.PublicAddress,
			L4: &scmp.Hdr{
				Class: scmp.C_General, Type: scmp.T_G_RecordPathReply,
				TotalLen: 40,
				Checksum: common.RawBytes{0x38, 0xbb},
			},
			Pld: &scmp.Payload{
				Meta: &scmp.Meta{
					InfoLen: uint8((&scmp.InfoRecordPath{}).Len()),
				},
				Info:    &scmp.InfoRecordPath{Id: 0xf00dcafe, Entries: []*scmp.RecordPathEntry{}},
				CmnHdr:  common.RawBytes{},
				AddrHdr: common.RawBytes{},
				PathHdr: common.RawBytes{},
				ExtHdrs: common.RawBytes{},
				L4Hdr:   common.RawBytes{},
			},
		},
	},
}

func TestDataplaneIntegration(t *testing.T) {
	settings := InitTestSettings(t)

	go func() {
		err := RunDispatcher(settings.ApplicationSocket, settings.OverlayPort)
		if err != nil {
			t.Fatalf("dispatcher error, err = %v", err)
		}
	}()
	time.Sleep(defaultWaitDuration)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			conn, _, err := reliable.RegisterTimeout(
				settings.ApplicationSocket,
				tc.ClientAddress.IA,
				&addr.AppAddr{L3: tc.ClientAddress.PublicAddress, L4: tc.ClientAddress.PublicPort},
				nil,
				tc.ClientAddress.ServiceAddress,
				defaultTimeout,
			)
			if err != nil {
				t.Fatalf("unable to open socket, err = %v", err)
			}

			send_buffer := make([]byte, common.MaxMTU)
			n, err := hpkt.WriteScnPkt(tc.TestPacket, send_buffer)
			if err != nil {
				t.Fatalf("unable to serialize packet for sending, err = %v", err)
			}
			send_buffer = send_buffer[:n]

			if _, err := conn.WriteTo(send_buffer, tc.OverlayAddress); err != nil {
				t.Fatalf("unable to write message, err = %v", err)
			}

			if err := conn.SetReadDeadline(time.Now().Add(defaultTimeout)); err != nil {
				t.Fatalf("unable to set read deadline, err = %v", err)
			}

			recv_buffer := make([]byte, common.MaxMTU)
			n, _, err = conn.ReadFrom(recv_buffer)
			if err != nil {
				t.Fatalf("unable to read message, err = %v", err)
			}
			recv_buffer = recv_buffer[:n]

			var packet spkt.ScnPkt
			if err := hpkt.ParseScnPkt(&packet, recv_buffer); err != nil {
				t.Fatalf("unable to parse received packet, err = %v", err)
			}

			if err := conn.Close(); err != nil {
				t.Errorf("error closing conn, err = %v", err)
			}

			if !reflect.DeepEqual(&packet, tc.ExpectedPacket) {
				t.Errorf("bad message received, have %#v, expect %#v", packet, tc.ExpectedPacket)
				t.Errorf("== headers: have %#v, expect %#v", packet.L4, tc.ExpectedPacket.L4)
				t.Errorf("== payload: have %#v, expect %#v", packet.Pld, tc.ExpectedPacket.Pld)
			}
		})
		time.Sleep(defaultWaitDuration)
	}
}

func MustNewOverlayAddr(l3 addr.HostAddr, l4 addr.L4Info) *overlay.OverlayAddr {
	address, err := overlay.NewOverlayAddr(l3, l4)
	if err != nil {
		panic(err)
	}
	return address
}

func TestMain(m *testing.M) {
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}
