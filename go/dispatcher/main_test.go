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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/xtest"
)

const (
	defaultTimeout      = 2 * time.Second
	defaultWaitDuration = 200 * time.Millisecond
)

type TestSettings struct {
	ApplicationSocket string
	UnderlayPort      int
	HeaderV2          bool
}

func InitTestSettings(t *testing.T, dispatcherTestPort int) *TestSettings {
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

type LegacyTestCase struct {
	Name            string
	ClientAddress   *ClientAddress
	TestPackets     []*spkt.ScnPkt
	UnderlayAddress *net.UDPAddr
	ExpectedPacket  *spkt.ScnPkt
}

type TestCase struct {
	Name            string
	ClientAddress   *ClientAddress
	TestPackets     []*snet.Packet
	UnderlayAddress *net.UDPAddr
	ExpectedPacket  *snet.Packet
}

func genLegacyTestCases(dispatcherPort int) []*LegacyTestCase {
	// Addressing information
	var (
		commonIA              = xtest.MustParseIA("1-ff00:0:1")
		commonPublicL3Address = addr.HostFromIP(net.IP{127, 0, 0, 1})
		commonUnderlayAddress = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: dispatcherPort}
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
			ServiceAddress:  addr.SvcCS,
			UnderlayAddress: commonUnderlayAddress,
		}
	)

	var testCases = []*LegacyTestCase{
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
					Checksum: common.RawBytes{0x37, 0xa9},
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
						L4Hdr: MustPackLegacyL4Header(&l4.UDP{SrcPort: clientXAddress.PublicPort}),
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
					L4Hdr:   MustPackLegacyL4Header(&l4.UDP{SrcPort: clientXAddress.PublicPort}),
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
					Info: &scmp.InfoRecordPath{
						Id:      0xf00dcafe,
						Entries: []*scmp.RecordPathEntry{},
					},
					CmnHdr:  common.RawBytes{},
					AddrHdr: common.RawBytes{},
					PathHdr: common.RawBytes{},
					ExtHdrs: common.RawBytes{},
					L4Hdr:   common.RawBytes{},
				},
			},
		},
	}
	return testCases
}

func genTestCases(dispatcherPort int) []*TestCase {
	// Addressing information
	var (
		commonIA              = xtest.MustParseIA("1-ff00:0:1")
		commonPublicL3Address = addr.HostFromIP(net.IP{127, 0, 0, 1})
		commonUnderlayAddress = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: dispatcherPort}
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
			ServiceAddress:  addr.SvcCS,
			UnderlayAddress: commonUnderlayAddress,
		}
	)

	var testCases = []*TestCase{
		{
			Name:          "UDP/IPv4 packet",
			ClientAddress: clientXAddress,
			TestPackets: []*snet.Packet{
				{
					PacketInfo: snet.PacketInfo{
						Source: snet.SCIONAddress{
							IA:   clientXAddress.IA,
							Host: clientXAddress.PublicAddress,
						},
						Destination: snet.SCIONAddress{
							IA:   clientXAddress.IA,
							Host: clientXAddress.PublicAddress,
						},
						PayloadV2: snet.UDPPayload{
							SrcPort: clientXAddress.PublicPort,
							DstPort: clientXAddress.PublicPort,
							Payload: []byte{1, 2, 3, 4},
						},
					},
				},
			},
			UnderlayAddress: clientXAddress.UnderlayAddress,
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   clientXAddress.IA,
						Host: clientXAddress.PublicAddress,
					},
					Destination: snet.SCIONAddress{
						IA:   clientXAddress.IA,
						Host: clientXAddress.PublicAddress,
					},
					PayloadV2: snet.UDPPayload{
						SrcPort: clientXAddress.PublicPort,
						DstPort: clientXAddress.PublicPort,
						Payload: []byte{1, 2, 3, 4},
					},
				},
			},
		},
		{
			Name:          "UDP/SVC packet",
			ClientAddress: clientYAddress,
			TestPackets: []*snet.Packet{
				{
					PacketInfo: snet.PacketInfo{
						Source: snet.SCIONAddress{
							IA:   clientYAddress.IA,
							Host: clientYAddress.PublicAddress,
						},
						Destination: snet.SCIONAddress{
							IA:   clientYAddress.IA,
							Host: clientYAddress.ServiceAddress,
						},
						PayloadV2: snet.UDPPayload{
							SrcPort: clientYAddress.PublicPort,
							DstPort: clientYAddress.PublicPort,
							Payload: []byte{5, 6, 7, 8},
						},
					},
				},
			},
			UnderlayAddress: clientXAddress.UnderlayAddress,
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   clientYAddress.IA,
						Host: clientYAddress.PublicAddress,
					},
					Destination: snet.SCIONAddress{
						IA:   clientYAddress.IA,
						Host: clientYAddress.ServiceAddress,
					},
					PayloadV2: snet.UDPPayload{
						SrcPort: clientYAddress.PublicPort,
						DstPort: clientYAddress.PublicPort,
						Payload: []byte{5, 6, 7, 8},
					},
				},
			},
		},
		{
			Name:            "SCMP::Error, UDP quote",
			ClientAddress:   clientXAddress,
			UnderlayAddress: clientXAddress.UnderlayAddress,
			TestPackets: []*snet.Packet{
				{
					PacketInfo: snet.PacketInfo{
						Source: snet.SCIONAddress{
							IA:   clientXAddress.IA,
							Host: clientXAddress.PublicAddress,
						},
						Destination: snet.SCIONAddress{
							IA:   clientXAddress.IA,
							Host: clientXAddress.PublicAddress,
						},
						PayloadV2: snet.SCMPDestinationUnreachable{
							Payload: MustPack(snet.Packet{
								PacketInfo: snet.PacketInfo{
									Source: snet.SCIONAddress{
										IA:   clientXAddress.IA,
										Host: clientXAddress.PublicAddress,
									},
									Destination: snet.SCIONAddress{
										IA:   clientXAddress.IA,
										Host: clientXAddress.PublicAddress,
									},
									PayloadV2: snet.UDPPayload{SrcPort: clientXAddress.PublicPort},
								},
							}),
						},
					},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   clientXAddress.IA,
						Host: clientXAddress.PublicAddress,
					},
					Destination: snet.SCIONAddress{
						IA:   clientXAddress.IA,
						Host: clientXAddress.PublicAddress,
					},
					PayloadV2: snet.SCMPDestinationUnreachable{
						Payload: MustPack(snet.Packet{
							PacketInfo: snet.PacketInfo{
								Source: snet.SCIONAddress{
									IA:   clientXAddress.IA,
									Host: clientXAddress.PublicAddress,
								},
								Destination: snet.SCIONAddress{
									IA:   clientXAddress.IA,
									Host: clientXAddress.PublicAddress,
								},
								PayloadV2: snet.UDPPayload{SrcPort: clientXAddress.PublicPort},
							},
						}),
					},
				},
			},
		},
		{
			Name:            "SCMP::Error, SCMP quote",
			ClientAddress:   clientXAddress,
			UnderlayAddress: clientXAddress.UnderlayAddress,
			TestPackets: []*snet.Packet{
				{
					// Force a SCMP General ID registration to happen, but route it
					// from nowhere so we don't get it back
					PacketInfo: snet.PacketInfo{
						Source: snet.SCIONAddress{
							IA:   xtest.MustParseIA("1-ff00:0:42"), // middle of nowhere
							Host: clientXAddress.PublicAddress,
						},
						Destination: snet.SCIONAddress{
							IA:   clientYAddress.IA,
							Host: clientYAddress.PublicAddress,
						},
						PayloadV2: snet.SCMPEchoRequest{Identifier: 0xdead},
					},
				},
				{
					PacketInfo: snet.PacketInfo{
						Source: snet.SCIONAddress{
							IA:   clientXAddress.IA,
							Host: clientXAddress.PublicAddress,
						},
						Destination: snet.SCIONAddress{
							IA:   clientXAddress.IA,
							Host: clientXAddress.PublicAddress,
						},
						PayloadV2: snet.SCMPDestinationUnreachable{
							Payload: MustPack(snet.Packet{
								PacketInfo: snet.PacketInfo{
									Source: snet.SCIONAddress{
										IA:   clientXAddress.IA,
										Host: clientXAddress.PublicAddress,
									},
									Destination: snet.SCIONAddress{
										IA:   clientXAddress.IA,
										Host: clientXAddress.PublicAddress,
									},
									PayloadV2: snet.SCMPEchoRequest{Identifier: 0xdead},
								},
							}),
						},
					},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   clientXAddress.IA,
						Host: clientXAddress.PublicAddress,
					},
					Destination: snet.SCIONAddress{
						IA:   clientXAddress.IA,
						Host: clientXAddress.PublicAddress,
					},
					PayloadV2: snet.SCMPDestinationUnreachable{
						Payload: MustPack(snet.Packet{
							PacketInfo: snet.PacketInfo{
								Source: snet.SCIONAddress{
									IA:   clientXAddress.IA,
									Host: clientXAddress.PublicAddress,
								},
								Destination: snet.SCIONAddress{
									IA:   clientXAddress.IA,
									Host: clientXAddress.PublicAddress,
								},
								PayloadV2: snet.SCMPEchoRequest{Identifier: 0xdead},
							},
						}),
					},
				},
			},
		},
		{
			Name:            "SCMP::General::EchoRequest",
			ClientAddress:   clientXAddress,
			UnderlayAddress: clientYAddress.UnderlayAddress,
			TestPackets: []*snet.Packet{
				{
					PacketInfo: snet.PacketInfo{
						Source: snet.SCIONAddress{
							IA:   clientXAddress.IA,
							Host: clientXAddress.PublicAddress,
						},
						Destination: snet.SCIONAddress{
							IA:   clientYAddress.IA,
							Host: clientYAddress.PublicAddress,
						},
						PayloadV2: snet.SCMPEchoRequest{
							Identifier: 0xdead,
							SeqNumber:  0xcafe,
							Payload:    []byte("hello?"),
						},
					},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   clientYAddress.IA,
						Host: clientYAddress.PublicAddress,
					},
					Destination: snet.SCIONAddress{
						IA:   clientXAddress.IA,
						Host: clientXAddress.PublicAddress,
					},
					PayloadV2: snet.SCMPEchoReply{
						Identifier: 0xdead,
						SeqNumber:  0xcafe,
						Payload:    []byte("hello?"),
					},
				},
			},
		},
		{
			Name:            "SCMP::General::TraceRouteRequest",
			ClientAddress:   clientXAddress,
			UnderlayAddress: clientYAddress.UnderlayAddress,
			TestPackets: []*snet.Packet{
				{
					PacketInfo: snet.PacketInfo{
						Source: snet.SCIONAddress{
							IA:   clientXAddress.IA,
							Host: clientXAddress.PublicAddress,
						},
						Destination: snet.SCIONAddress{
							IA:   clientYAddress.IA,
							Host: clientYAddress.PublicAddress,
						},
						PayloadV2: snet.SCMPTracerouteRequest{Identifier: 0xdeaf, Sequence: 0xcafd},
					},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   clientYAddress.IA,
						Host: clientYAddress.PublicAddress,
					},
					Destination: snet.SCIONAddress{
						IA:   clientXAddress.IA,
						Host: clientXAddress.PublicAddress,
					},
					PayloadV2: snet.SCMPTracerouteReply{Identifier: 0xdeaf, Sequence: 0xcafd},
				},
			},
		},
	}
	return testCases
}

func TestDataplaneIntegration(t *testing.T) {
	dispatcherTestPort := 40032
	settings := InitTestSettings(t, dispatcherTestPort)
	settings.HeaderV2 = true

	go func() {
		err := RunDispatcher(false, settings.ApplicationSocket, reliable.DefaultDispSocketFileMode,
			settings.UnderlayPort, settings.HeaderV2)
		require.NoError(t, err, "dispatcher error")
	}()
	time.Sleep(defaultWaitDuration)

	testCases := genTestCases(dispatcherTestPort)
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
	require.NoError(t, err, "unable to open socket")
	// Always destroy the connection s.t. future tests aren't compromised by a
	// fatal in this subtest
	defer conn.Close()

	for _, packet := range tc.TestPackets {
		require.NoError(t, packet.Serialize())
		fmt.Printf("sending packet: %x\n", packet.Bytes)
		_, err = conn.WriteTo(packet.Bytes, tc.UnderlayAddress)
		require.NoError(t, err, "unable to write message")
	}

	err = conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	require.NoError(t, err, "unable to set read deadline")

	rcvPkt := snet.Packet{}
	rcvPkt.Prepare()
	n, _, err := conn.ReadFrom(rcvPkt.Bytes)
	require.NoError(t, err, "unable to read message")
	rcvPkt.Bytes = rcvPkt.Bytes[:n]

	require.NoError(t, rcvPkt.Decode())

	err = conn.Close()
	require.NoError(t, err, "unable to close conn")

	assert.Equal(t, tc.ExpectedPacket.PacketInfo, rcvPkt.PacketInfo)
}

func RunLegacyTestCase(t *testing.T, tc *LegacyTestCase, settings *TestSettings) {
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
	require.NoError(t, err, "unable to open socket")
	// Always destroy the connection s.t. future tests aren't compromised by a
	// fatal in this subtest
	defer conn.Close()

	for _, packet := range tc.TestPackets {
		sendBuffer := make([]byte, common.MaxMTU)
		n, err := hpkt.WriteScnPkt(packet, sendBuffer)
		require.NoError(t, err, "unable to serialize packet for sending")
		sendBuffer = sendBuffer[:n]

		fmt.Printf("sending packet: %x\n", sendBuffer)
		_, err = conn.WriteTo(sendBuffer, tc.UnderlayAddress)
		require.NoError(t, err, "unable to write message")
	}

	err = conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	require.NoError(t, err, "unable to set read deadline")

	recvBuffer := make([]byte, common.MaxMTU)
	n, _, err := conn.ReadFrom(recvBuffer)
	require.NoError(t, err, "unable to read message")
	recvBuffer = recvBuffer[:n]

	var packet spkt.ScnPkt
	err = hpkt.ParseScnPkt(&packet, recvBuffer)
	require.NoError(t, err, "unable to parse received packet")

	err = conn.Close()
	require.NoError(t, err, "unable to close conn")

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

func MustPack(pkt snet.Packet) []byte {
	if err := pkt.Serialize(); err != nil {
		panic(err)
	}
	return pkt.Bytes
}

func MustPackLegacyL4Header(header l4.L4Header) common.RawBytes {
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
	// log.Setup(log.Config{Console: log.ConsoleConfig{Level: "debug"}})
	os.Exit(m.Run())
}

func generatePath() []byte {
	return []byte{
		0x0, 0x0, 0x20, 0x80, 0x0, 0x0, 0x1, 0x11,
		0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0x22,
		0x0, 0x0, 0x1, 0x0, 0x0, 0x3f, 0x0, 0x1,
		0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x0,
		0x3f, 0x0, 0x3, 0x0, 0x2, 0x1, 0x2, 0x3,
		0x4, 0x5, 0x6, 0x0, 0x3f, 0x0, 0x0, 0x0,
		0x2, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x0,
		0x3f, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2, 0x3,
		0x4, 0x5, 0x6,
	}
}
