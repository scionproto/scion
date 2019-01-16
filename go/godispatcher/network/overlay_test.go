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

package network

import (
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/l4/mock_l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestComputeDestination(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	badL4 := mock_l4.NewMockL4Header(ctrl)
	badL4.EXPECT().Pack(gomock.Any()).Return(common.RawBytes{}, nil).AnyTimes()
	badL4.EXPECT().L4Type().Return(common.L4TCP).AnyTimes()

	type TestCase struct {
		Description string
		Packet      *spkt.ScnPkt
		ExpectedDst Destination
		ExpectedErr string
	}
	var testCases = []*TestCase{
		{
			Description: "SCION/L4 returns error if L4 is not UDP or SCMP",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4:      badL4,
			},
			ExpectedErr: ErrUnsupportedL4,
		},
		{
			Description: "SCION/UDP with IP destination is delivered by IP",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4:      &l4.UDP{DstPort: 1002},
			},
			ExpectedDst: &UDPDestination{IP: net.IP{192, 168, 0, 1}, Port: 1002},
		},
		{
			Description: "SCION/UDP with SVC destination is delivered by SVC",
			Packet: &spkt.ScnPkt{
				DstHost: addr.SvcPS,
				L4:      &l4.UDP{DstPort: 1002},
			},
			ExpectedDst: SVCDestination(addr.SvcPS),
		},
		{
			Description: "SCION/UDP without SVC or IP destination returns error",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostNone{},
				L4:      &l4.UDP{DstPort: 1002},
			},
			ExpectedErr: ErrUnsupportedDestination,
		},
		{
			Description: "SCION/SCMP, General::EchoRequest, is sent to SCMP handler",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4:      &scmp.Hdr{Class: scmp.C_General, Type: scmp.T_G_EchoRequest},
				Pld: &scmp.Payload{
					Info: &scmp.InfoEcho{
						Id: 0xdeadbeef,
					},
				},
			},
			ExpectedDst: SCMPHandlerDestination{},
		},
		{
			Description: "SCION/SCMP, General::EchoReply, is delivered by IP and ID",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4:      &scmp.Hdr{Class: scmp.C_General, Type: scmp.T_G_EchoReply},
				Pld: &scmp.Payload{
					Info: &scmp.InfoEcho{
						Id: 0xdeadbeef,
					},
				},
			},
			ExpectedDst: &SCMPAppDestination{ID: 0xdeadbeef},
		},
		{
			Description: "SCION/SCMP with General::RecordPathRequest, is sent to SCMP handler",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4:      &scmp.Hdr{Class: scmp.C_General, Type: scmp.T_G_RecordPathRequest},
				Pld: &scmp.Payload{
					Info: &scmp.InfoRecordPath{
						Id: 0xdeadbeef,
					},
				},
			},
			ExpectedDst: SCMPHandlerDestination{},
		},
		{
			Description: "SCION/SCMP with General::RecordPathReply, is delivered by IP and ID",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4:      &scmp.Hdr{Class: scmp.C_General, Type: scmp.T_G_RecordPathReply},
				Pld: &scmp.Payload{
					Info: &scmp.InfoRecordPath{
						Id: 0xdeadbeef,
					},
				},
			},
			ExpectedDst: &SCMPAppDestination{ID: 0xdeadbeef},
		},
		{
			Description: "SCION/SCMP with General::TraceRouteRequest, is sent to SCMP handler",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4:      &scmp.Hdr{Class: scmp.C_General, Type: scmp.T_G_TraceRouteRequest},
				Pld: &scmp.Payload{
					Info: &scmp.InfoTraceRoute{
						Id: 0xdeadbeef,
					},
				},
			},
			ExpectedDst: SCMPHandlerDestination{},
		},
		{
			Description: "SCION/SCMP with General::TraceRouteReply, is delivered by IP and ID",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4:      &scmp.Hdr{Class: scmp.C_General, Type: scmp.T_G_TraceRouteReply},
				Pld: &scmp.Payload{
					Info: &scmp.InfoTraceRoute{
						Id: 0xdeadbeef,
					},
				},
			},
			ExpectedDst: &SCMPAppDestination{ID: 0xdeadbeef},
		},
		{
			Description: "SCION/SCMP with non-IP destination returns error",
			Packet: &spkt.ScnPkt{
				DstHost: addr.SvcPS,
				L4:      &scmp.Hdr{Class: scmp.C_General, Type: scmp.T_G_EchoRequest},
			},
			ExpectedErr: ErrUnsupportedSCMPDestination,
		},
		{
			Description: "SCION/SCMP with Non-General class and UDP quote is delivered by " +
				"SCION Header destination IP + Quoted L4 UDP port",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4:      &scmp.Hdr{Class: scmp.C_Routing},
				Pld: &scmp.Payload{
					Meta: &scmp.Meta{
						L4Proto: common.L4UDP,
					},
					L4Hdr: MustPackL4Header(t, &l4.UDP{
						SrcPort: 1002,
					}),
				},
			},
			ExpectedDst: &UDPDestination{IP: net.IP{192, 168, 0, 1}, Port: 1002},
		},
		{
			Description: "SCION/SCMP with Non-General class and bad quoted L4 type returns error",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4:      &scmp.Hdr{Class: scmp.C_Routing},
				Pld: &scmp.Payload{
					Meta: &scmp.Meta{
						L4Proto: badL4.L4Type(),
					},
					L4Hdr: MustPackL4Header(t, badL4),
				},
			},
			ExpectedErr: ErrUnsupportedQuotedL4Type,
		},
		{
			Description: "SCION/SCMP with Non-General::*, errors out if quoted L4 is malformed",
			Packet: &spkt.ScnPkt{
				DstHost: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4:      &scmp.Hdr{Class: scmp.C_Routing},
				Pld: &scmp.Payload{
					Meta: &scmp.Meta{
						L4Proto: common.L4UDP,
					},
					L4Hdr: common.RawBytes{1, 2},
				},
			},
			ExpectedErr: ErrMalformedL4Quote,
		},
	}
	Convey("", t, func() {
		for _, test := range testCases {
			Convey(test.Description, func() {
				destination, err := ComputeDestination(test.Packet)
				xtest.SoMsgErrorStr("err", err, test.ExpectedErr)
				SoMsg("destination", destination, ShouldResemble, test.ExpectedDst)
			})
		}
	})
}

func MustPackL4Header(t *testing.T, header l4.L4Header) common.RawBytes {
	b, err := header.Pack(false)
	xtest.FailOnErr(t, err)
	return b
}
