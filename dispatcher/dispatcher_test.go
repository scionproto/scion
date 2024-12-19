// Copyright 2023 ETH Zurich
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

package dispatcher

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

type testCase struct {
	Name           string
	IsDispatcher   bool
	ClientAddrPort netip.AddrPort
	DispAddrPort   netip.AddrPort
	Pkt            *snet.Packet
	ExpectedValue  bool
}

func testRunTestCase(t *testing.T, tc testCase) {
	serverConn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(tc.DispAddrPort))
	require.NoError(t, err)
	defer serverConn.Close()
	setIPPktInfo(serverConn)
	emptyTopo := make(map[addr.Addr]netip.AddrPort)
	server := NewServer(tc.IsDispatcher, emptyTopo, serverConn)

	clientConn, err := net.DialUDP(
		"udp",
		net.UDPAddrFromAddrPort(tc.ClientAddrPort),
		net.UDPAddrFromAddrPort(tc.DispAddrPort),
	)
	require.NoError(t, err)
	defer clientConn.Close()
	require.NoError(t, tc.Pkt.Serialize())
	_, err = clientConn.Write(tc.Pkt.Bytes)
	require.NoError(t, err)

	buf := make([]byte, 1024)
	oobuf := make([]byte, 1024)
	n, nn, _, nextHop, err := server.conn.ReadMsgUDPAddrPort(buf, oobuf)
	require.NoError(t, err)
	var underlayAddr netip.Addr
	if tc.IsDispatcher {
		underlayAddr = server.parseUnderlayAddr(oobuf[:nn])
		require.NotNil(t, underlayAddr)
	}
	_, dstAddr, err := server.processMsgNextHop(buf[:n], underlayAddr, nextHop)
	assert.NoError(t, err)
	assert.Equal(t, tc.ExpectedValue, dstAddr.IsValid())
}

func TestValidateAddr(t *testing.T) {
	clientAddr := netip.MustParseAddr("127.0.0.1")
	clientHost := addr.HostIP(clientAddr)
	clientAddrPort := netip.AddrPortFrom(clientAddr, 0)
	dispIPv4Addr := netip.MustParseAddr("127.0.0.1")
	dispIPv4Host := addr.HostIP(dispIPv4Addr)
	dispIPv4AddrPort := netip.AddrPortFrom(dispIPv4Addr, 40032)
	clientIPv6Addr := netip.MustParseAddr("::1")
	clientIPv6Host := addr.HostIP(clientIPv6Addr)
	clientIPv6AddrPort := netip.AddrPortFrom(clientIPv6Addr, 0)
	dispIPv6Addr := netip.MustParseAddr("::1")
	dispIPv6Host := addr.HostIP(dispIPv6Addr)
	dispIPv6AddrPort := netip.AddrPortFrom(dispIPv6Addr, 40032)

	testCases := []testCase{
		{
			Name:           "valid UDP/IPv4",
			IsDispatcher:   true,
			ClientAddrPort: clientAddrPort,
			DispAddrPort:   dispIPv4AddrPort,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:2"),
						Host: clientHost,
					},
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:1"),
						Host: dispIPv4Host,
					},
					Payload: snet.UDPPayload{
						SrcPort: 20001,
						DstPort: 40001,
					},
					Path: path.Empty{},
				},
			},
			ExpectedValue: true,
		},
		{
			Name:           "invalid UDP/IPv4",
			IsDispatcher:   true,
			ClientAddrPort: clientAddrPort,
			DispAddrPort:   dispIPv4AddrPort,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:2"),
						Host: clientHost,
					},
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:1"),
						Host: addr.MustParseHost("127.0.0.2"),
					},
					Payload: snet.UDPPayload{
						SrcPort: 20001,
						DstPort: 40001,
					},
					Path: path.Empty{},
				},
			},
			ExpectedValue: false,
		},
		{
			Name:           "valid SCMP/IPv4",
			IsDispatcher:   true,
			ClientAddrPort: clientAddrPort,
			DispAddrPort:   dispIPv4AddrPort,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:2"),
						Host: clientHost,
					},
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:1"),
						Host: dispIPv4Host,
					},
					Payload: snet.SCMPDestinationUnreachable{
						Payload: MustPack(snet.Packet{
							PacketInfo: snet.PacketInfo{
								Source: snet.SCIONAddress{
									IA:   addr.MustParseIA("1-ff00:0:2"),
									Host: dispIPv4Host,
								},
								Destination: snet.SCIONAddress{
									IA:   addr.MustParseIA("1-ff00:0:1"),
									Host: clientHost,
								},
								Payload: snet.SCMPEchoRequest{Identifier: 0xdead},
								Path:    path.Empty{},
							},
						}),
					},
					Path: path.Empty{},
				},
			},
			ExpectedValue: true,
		},
		{
			Name:           "invalid SCMP/IPv4",
			IsDispatcher:   true,
			ClientAddrPort: clientAddrPort,
			DispAddrPort:   dispIPv4AddrPort,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:2"),
						Host: clientHost,
					},
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:1"),
						Host: addr.MustParseHost("127.0.0.2"),
					},
					Payload: snet.SCMPDestinationUnreachable{
						Payload: MustPack(snet.Packet{
							PacketInfo: snet.PacketInfo{
								Source: snet.SCIONAddress{
									IA:   addr.MustParseIA("1-ff00:0:2"),
									Host: dispIPv4Host,
								},
								Destination: snet.SCIONAddress{
									IA:   addr.MustParseIA("1-ff00:0:1"),
									Host: clientHost,
								},
								Payload: snet.SCMPEchoRequest{Identifier: 0xdead},
								Path:    path.Empty{},
							},
						}),
					},
					Path: path.Empty{},
				},
			},
			ExpectedValue: false,
		},
		{
			Name:           "valid UDP/IPv6",
			IsDispatcher:   true,
			ClientAddrPort: clientIPv6AddrPort,
			DispAddrPort:   dispIPv6AddrPort,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:2"),
						Host: clientIPv6Host,
					},
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:1"),
						Host: dispIPv6Host,
					},
					Payload: snet.UDPPayload{
						SrcPort: 20001,
						DstPort: 40001,
					},
					Path: path.Empty{},
				},
			},
			ExpectedValue: true,
		},
		{
			Name:           "invalid UDP/IPv6",
			IsDispatcher:   true,
			ClientAddrPort: clientIPv6AddrPort,
			DispAddrPort:   dispIPv6AddrPort,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:2"),
						Host: clientHost,
					},
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:1"),
						Host: addr.MustParseHost("::2"),
					},
					Payload: snet.UDPPayload{
						SrcPort: 20001,
						DstPort: 40001,
					},
					Path: path.Empty{},
				},
			},
			ExpectedValue: false,
		},
		{
			Name:           "valid SCMP/IPv6",
			IsDispatcher:   true,
			ClientAddrPort: clientIPv6AddrPort,
			DispAddrPort:   dispIPv6AddrPort,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:2"),
						Host: clientIPv6Host,
					},
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:1"),
						Host: dispIPv6Host,
					},
					Payload: snet.SCMPDestinationUnreachable{
						Payload: MustPack(snet.Packet{
							PacketInfo: snet.PacketInfo{
								Source: snet.SCIONAddress{
									IA:   addr.MustParseIA("1-ff00:0:2"),
									Host: dispIPv6Host,
								},
								Destination: snet.SCIONAddress{
									IA:   addr.MustParseIA("1-ff00:0:1"),
									Host: clientIPv6Host,
								},
								Payload: snet.SCMPEchoRequest{Identifier: 0xdead},
								Path:    path.Empty{},
							},
						}),
					},
					Path: path.Empty{},
				},
			},
			ExpectedValue: true,
		},
		{
			Name:           "invalid SCMP/IPv6",
			IsDispatcher:   true,
			ClientAddrPort: clientIPv6AddrPort,
			DispAddrPort:   dispIPv6AddrPort,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:2"),
						Host: clientIPv6Host,
					},
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:1"),
						Host: addr.MustParseHost("::2"),
					},
					Payload: snet.SCMPDestinationUnreachable{
						Payload: MustPack(snet.Packet{
							PacketInfo: snet.PacketInfo{
								Source: snet.SCIONAddress{
									IA:   addr.MustParseIA("1-ff00:0:2"),
									Host: dispIPv6Host,
								},
								Destination: snet.SCIONAddress{
									IA:   addr.MustParseIA("1-ff00:0:1"),
									Host: clientIPv6Host,
								},
								Payload: snet.SCMPEchoRequest{Identifier: 0xdead},
								Path:    path.Empty{},
							},
						}),
					},
					Path: path.Empty{},
				},
			},
			ExpectedValue: false,
		},
		{
			Name:           "IPv4-mapped-IPv6 to IPv4",
			IsDispatcher:   true,
			ClientAddrPort: clientAddrPort,
			DispAddrPort:   dispIPv4AddrPort,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:2"),
						Host: clientHost,
					},
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:1"),
						Host: addr.HostIP(netip.AddrFrom16(dispIPv4Addr.As16())),
					},
					Payload: snet.UDPPayload{
						SrcPort: 20001,
						DstPort: 40001,
					},
					Path: path.Empty{},
				},
			},
			ExpectedValue: true,
		},
		{
			Name:           "isn't dispatcher",
			IsDispatcher:   false,
			ClientAddrPort: clientAddrPort,
			DispAddrPort:   dispIPv4AddrPort,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:2"),
						Host: clientHost,
					},
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:1"),
						Host: dispIPv4Host,
					},
					Payload: snet.UDPPayload{
						SrcPort: 20001,
						DstPort: 40001,
					},
					Path: path.Empty{},
				},
			},
			ExpectedValue: false,
		},
	}
	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			testRunTestCase(t, test)
		})
	}

}

func MustPack(pkt snet.Packet) []byte {
	if err := pkt.Serialize(); err != nil {
		panic(err)
	}
	return pkt.Bytes
}
