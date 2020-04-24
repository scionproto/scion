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
	"context"
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
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/xtest"
)

const (
	dispatcherTestPort  = 40031
	defaultTimeout      = 2 * time.Second
	defaultWaitDuration = 200 * time.Millisecond
)

type TestSettings struct {
	ApplicationSocket string
	UnderlayPort      int
}

func InitTestSettings(t *testing.T) *TestSettings {
	socketName, err := getSocketName("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	return &TestSettings{
		ApplicationSocket: socketName,
		UnderlayPort:      int(dispatcherTestPort),
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
	IA              addr.IA
	PublicAddress   addr.HostAddr
	PublicPort      uint16
	ServiceAddress  addr.HostSVC
	UnderlayAddress *net.UDPAddr
	UnderlayPort    uint16
}

// Addressing information
var (
	commonIA              = xtest.MustParseIA("1-ff00:0:1")
	commonPublicL3Address = addr.HostFromIP(net.IP{127, 0, 0, 1})
	commonUnderlayAddress = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: dispatcherTestPort}
	clientXAddress        = &ClientAddress{
		IA:              commonIA,
		PublicAddress:   commonPublicL3Address,
		PublicPort:      8080,
		ServiceAddress:  addr.SvcNone,
		UnderlayAddress: commonUnderlayAddress,
	}
	clientYAddress = &ClientAddress{
		IA:              commonIA,
		PublicAddress:   commonPublicL3Address,
		PublicPort:      8081,
		ServiceAddress:  addr.SvcPS,
		UnderlayAddress: commonUnderlayAddress,
	}
)

type TestCase struct {
	Name            string
	ClientAddress   *ClientAddress
	TestPackets     []*spkt.ScnPkt
	UnderlayAddress *net.UDPAddr
	ExpectedPacket  *spkt.ScnPkt
}

var testCases = []*TestCase{
	{
		Name:          "UDP/IPv4 packet",
		ClientAddress: clientXAddress,
		TestPackets: []*spkt.ScnPkt{
			{
				SrcIA:   clientXAddress.IA,
				DstIA:   clientXAddress.IA,
				SrcHost: clientXAddress.PublicAddress,
				DstHost: clientXAddress.PublicAddress,
				L4: &l4.UDP{
					SrcPort: clientXAddress.PublicPort,
					DstPort: clientXAddress.PublicPort,
				},
				Pld: common.RawBytes{1, 2, 3, 4},
			},
		},
		UnderlayAddress: clientXAddress.UnderlayAddress,
		ExpectedPacket: &spkt.ScnPkt{
			SrcIA:   clientXAddress.IA,
			DstIA:   clientXAddress.IA,
			SrcHost: clientXAddress.PublicAddress,
			DstHost: clientXAddress.PublicAddress,
			L4: &l4.UDP{
				SrcPort:  clientXAddress.PublicPort,
				DstPort:  clientXAddress.PublicPort,
				TotalLen: 12,
				Checksum: common.RawBytes{0xc0, 0xb3},
			},
			Pld: common.RawBytes{1, 2, 3, 4},
		},
	},
	{
		Name:          "UDP/SVC packet",
		ClientAddress: clientYAddress,
		TestPackets: []*spkt.ScnPkt{
			{
				SrcIA:   clientYAddress.IA,
				DstIA:   clientYAddress.IA,
				SrcHost: clientYAddress.PublicAddress,
				DstHost: clientYAddress.ServiceAddress,
				L4: &l4.UDP{
					SrcPort: clientYAddress.PublicPort,
					DstPort: clientYAddress.PublicPort,
				},
				Pld: common.RawBytes{5, 6, 7, 8},
			},
		},
		UnderlayAddress: clientXAddress.UnderlayAddress,
		ExpectedPacket: &spkt.ScnPkt{
			SrcIA:   clientYAddress.IA,
			DstIA:   clientYAddress.IA,
			SrcHost: clientYAddress.PublicAddress,
			DstHost: clientYAddress.ServiceAddress,
			L4: &l4.UDP{
				SrcPort:  clientYAddress.PublicPort,
				DstPort:  clientYAddress.PublicPort,
				TotalLen: 12,
				Checksum: common.RawBytes{0x37, 0xaa},
			},
			Pld: common.RawBytes{5, 6, 7, 8},
		},
	},
	{
		Name:            "SCMP::Error, UDP quote",
		ClientAddress:   clientXAddress,
		UnderlayAddress: clientXAddress.UnderlayAddress,
		TestPackets: []*spkt.ScnPkt{
			{
				SrcIA:   clientXAddress.IA,
				DstIA:   clientXAddress.IA,
				SrcHost: clientXAddress.PublicAddress,
				DstHost: clientXAddress.PublicAddress,
				L4: &scmp.Hdr{
					Class: scmp.C_Routing, Type: scmp.T_R_UnreachNet,
				},
				Pld: &scmp.Payload{
					Meta:  &scmp.Meta{L4Proto: common.L4UDP, L4HdrLen: 1},
					L4Hdr: MustPackL4Header(&l4.UDP{SrcPort: clientXAddress.PublicPort}),
				},
			},
		},
		ExpectedPacket: &spkt.ScnPkt{
			SrcIA:   clientXAddress.IA,
			DstIA:   clientXAddress.IA,
			SrcHost: clientXAddress.PublicAddress,
			DstHost: clientXAddress.PublicAddress,
			L4: &scmp.Hdr{
				Class: scmp.C_Routing, Type: scmp.T_R_UnreachNet,
				TotalLen: 32,
				Checksum: common.RawBytes{0xd3, 0x43},
			},
			Pld: &scmp.Payload{
				Meta:    &scmp.Meta{L4Proto: common.L4UDP, L4HdrLen: 1},
				CmnHdr:  common.RawBytes{},
				AddrHdr: common.RawBytes{},
				PathHdr: common.RawBytes{},
				ExtHdrs: common.RawBytes{},
				L4Hdr:   MustPackL4Header(&l4.UDP{SrcPort: clientXAddress.PublicPort}),
			},
		},
	},
	{
		Name:            "SCMP::Error, SCMP quote",
		ClientAddress:   clientXAddress,
		UnderlayAddress: clientXAddress.UnderlayAddress,
		TestPackets: []*spkt.ScnPkt{
			{
				// Force a SCMP General ID registration to happen, but route it
				// from nowhere so we don't get it back
				SrcIA:   xtest.MustParseIA("1-ff00:0:42"), // middle of nowhere
				DstIA:   clientYAddress.IA,
				SrcHost: clientXAddress.PublicAddress,
				DstHost: clientYAddress.PublicAddress,
				L4: &scmp.Hdr{
					Class: scmp.C_General, Type: scmp.T_G_EchoRequest,
				},
				Pld: &scmp.Payload{
					Meta: &scmp.Meta{InfoLen: uint8((&scmp.InfoEcho{}).Len()) / 8},
					Info: &scmp.InfoEcho{Id: 0xabbacafe},
				},
			},
			{
				SrcIA:   clientXAddress.IA,
				DstIA:   clientXAddress.IA,
				SrcHost: clientXAddress.PublicAddress,
				DstHost: clientXAddress.PublicAddress,
				L4: &scmp.Hdr{
					Class: scmp.C_Routing, Type: scmp.T_R_UnreachNet,
				},
				Pld: &scmp.Payload{
					Meta: &scmp.Meta{
						L4Proto:  common.L4SCMP,
						L4HdrLen: 3 + uint8((&scmp.InfoEcho{}).Len()/common.LineLen),
					},
					L4Hdr: MustPackQuotedSCMPL4Header(
						&scmp.Hdr{
							Class: scmp.C_General,
							Type:  scmp.T_G_EchoRequest,
						},
						&scmp.Meta{
							InfoLen: uint8((&scmp.InfoEcho{}).Len()) / 8,
						},
						&scmp.InfoEcho{
							Id: 0xabbacafe,
						},
					),
				},
			},
		},
		ExpectedPacket: &spkt.ScnPkt{
			SrcIA:   clientXAddress.IA,
			DstIA:   clientXAddress.IA,
			SrcHost: clientXAddress.PublicAddress,
			DstHost: clientXAddress.PublicAddress,
			L4: &scmp.Hdr{
				Class: scmp.C_Routing, Type: scmp.T_R_UnreachNet,
				TotalLen: 64,
				Checksum: common.RawBytes{0x89, 0xf5},
			},
			Pld: &scmp.Payload{
				Meta: &scmp.Meta{
					L4Proto:  common.L4SCMP,
					L4HdrLen: 3 + uint8((&scmp.InfoEcho{}).Len()/common.LineLen),
				},
				CmnHdr:  common.RawBytes{},
				AddrHdr: common.RawBytes{},
				PathHdr: common.RawBytes{},
				ExtHdrs: common.RawBytes{},
				L4Hdr: MustPackQuotedSCMPL4Header(
					&scmp.Hdr{
						Class: scmp.C_General,
						Type:  scmp.T_G_EchoRequest,
					},
					&scmp.Meta{
						InfoLen: uint8((&scmp.InfoEcho{}).Len()) / 8,
					},
					&scmp.InfoEcho{
						Id: 0xabbacafe,
					},
				),
			},
		},
	},
	{
		Name:            "SCMP::General::EchoRequest",
		ClientAddress:   clientXAddress,
		UnderlayAddress: clientYAddress.UnderlayAddress,
		TestPackets: []*spkt.ScnPkt{
			{
				SrcIA:   clientXAddress.IA,
				DstIA:   clientYAddress.IA,
				SrcHost: clientXAddress.PublicAddress,
				DstHost: clientYAddress.PublicAddress,
				L4: &scmp.Hdr{
					Class: scmp.C_General, Type: scmp.T_G_EchoRequest,
				},
				Pld: &scmp.Payload{
					Meta: &scmp.Meta{InfoLen: uint8((&scmp.InfoEcho{}).Len())},
					Info: &scmp.InfoEcho{Id: 0xdeadcafe},
				},
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
				Checksum: common.RawBytes{0x4a, 0x1f},
			},
			Pld: &scmp.Payload{
				Meta: &scmp.Meta{
					InfoLen: uint8((&scmp.InfoEcho{}).Len()),
				},
				Info:    &scmp.InfoEcho{Id: 0xdeadcafe},
				CmnHdr:  common.RawBytes{},
				AddrHdr: common.RawBytes{},
				PathHdr: common.RawBytes{},
				ExtHdrs: common.RawBytes{},
				L4Hdr:   common.RawBytes{},
			},
		},
	},
	{
		Name:            "SCMP::General::TraceRouteRequest",
		ClientAddress:   clientXAddress,
		UnderlayAddress: clientYAddress.UnderlayAddress,
		TestPackets: []*spkt.ScnPkt{
			{
				SrcIA:   clientXAddress.IA,
				DstIA:   clientYAddress.IA,
				SrcHost: clientXAddress.PublicAddress,
				DstHost: clientYAddress.PublicAddress,
				L4: &scmp.Hdr{
					Class: scmp.C_General, Type: scmp.T_G_TraceRouteRequest,
				},
				Pld: &scmp.Payload{
					Meta: &scmp.Meta{InfoLen: uint8((&scmp.InfoTraceRoute{}).Len()) / 8},
					Info: &scmp.InfoTraceRoute{Id: 0xcafecafe},
				},
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
				Checksum: common.RawBytes{0x69, 0xbc},
			},
			Pld: &scmp.Payload{
				Meta: &scmp.Meta{
					InfoLen: uint8((&scmp.InfoTraceRoute{}).Len()) / 8,
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
		Name:            "SCMP::General::RecordPathRequest",
		ClientAddress:   clientXAddress,
		UnderlayAddress: clientYAddress.UnderlayAddress,
		TestPackets: []*spkt.ScnPkt{
			{
				SrcIA:   clientXAddress.IA,
				DstIA:   clientYAddress.IA,
				SrcHost: clientXAddress.PublicAddress,
				DstHost: clientYAddress.PublicAddress,
				L4: &scmp.Hdr{
					Class: scmp.C_General, Type: scmp.T_G_RecordPathRequest,
				},
				Pld: &scmp.Payload{
					Meta: &scmp.Meta{InfoLen: uint8((&scmp.InfoRecordPath{}).Len()) / 8},
					Info: &scmp.InfoRecordPath{Id: 0xf00dcafe},
				},
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
				Checksum: common.RawBytes{0x46, 0xbb},
			},
			Pld: &scmp.Payload{
				Meta: &scmp.Meta{
					InfoLen: uint8((&scmp.InfoRecordPath{}).Len()) / 8,
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
		err := RunDispatcher(false, settings.ApplicationSocket, reliable.DefaultDispSocketFileMode,
			settings.UnderlayPort)
		xtest.FailOnErr(t, err, "dispatcher error")
	}()
	time.Sleep(defaultWaitDuration)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			RunTestCase(t, tc, settings)
		})
		time.Sleep(defaultWaitDuration)
	}
}

func RunTestCase(t *testing.T, tc *TestCase, settings *TestSettings) {
	dispatcherService := reliable.NewDispatcher(settings.ApplicationSocket)
	ctx, cancelF := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancelF()
	conn, _, err := dispatcherService.Register(
		ctx,
		tc.ClientAddress.IA,
		&net.UDPAddr{
			IP:   tc.ClientAddress.PublicAddress.IP(),
			Port: int(tc.ClientAddress.PublicPort),
		},
		tc.ClientAddress.ServiceAddress,
	)
	xtest.FailOnErr(t, err, "unable to open socket")
	// Always destroy the connection s.t. future tests aren't compromised by a
	// fatal in this subtest
	defer conn.Close()

	for _, packet := range tc.TestPackets {
		send_buffer := make([]byte, common.MaxMTU)
		n, err := hpkt.WriteScnPkt(packet, send_buffer)
		xtest.FailOnErr(t, err, "unable to serialize packet for sending")
		send_buffer = send_buffer[:n]

		_, err = conn.WriteTo(send_buffer, tc.UnderlayAddress)
		xtest.FailOnErr(t, err, "unable to write message")
	}

	err = conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	xtest.FailOnErr(t, err, "unable to set read deadline")

	recv_buffer := make([]byte, common.MaxMTU)
	n, _, err := conn.ReadFrom(recv_buffer)
	xtest.FailOnErr(t, err, "unable to read message")
	recv_buffer = recv_buffer[:n]

	var packet spkt.ScnPkt
	err = hpkt.ParseScnPkt(&packet, recv_buffer)
	xtest.FailOnErr(t, err, "unable to parse received packet")

	err = conn.Close()
	xtest.FailOnErr(t, err, "unable to close conn")

	if !reflect.DeepEqual(&packet, tc.ExpectedPacket) {
		t.Errorf("bad message received, have %#v, expect %#v", &packet, tc.ExpectedPacket)
		if !reflect.DeepEqual(packet.L4, tc.ExpectedPacket.L4) {
			t.Errorf("== headers: have %#v, expect %#v", packet.L4, tc.ExpectedPacket.L4)
		}
		if !reflect.DeepEqual(packet.Pld, tc.ExpectedPacket.Pld) {
			t.Errorf("== payload: have %#v, expect %#v", packet.Pld, tc.ExpectedPacket.Pld)
		}
	}
}

func MustPackL4Header(header l4.L4Header) common.RawBytes {
	b, err := header.Pack(false)
	if err != nil {
		panic(err)
	}
	return b
}

func MustPackQuotedSCMPL4Header(header *scmp.Hdr, meta *scmp.Meta, info scmp.Info) common.RawBytes {
	b := make(common.RawBytes, common.MaxMTU)
	if err := header.Write(b); err != nil {
		panic(err)
	}
	if err := meta.Write(b[header.L4Len():]); err != nil {
		panic(err)
	}
	n, err := info.Write(b[header.L4Len()+common.LineLen:])
	if err != nil {
		panic(err)
	}
	return b[:header.L4Len()+common.LineLen+n]
}

func TestMain(m *testing.M) {
	log.Discard()
	os.Exit(m.Run())
}
