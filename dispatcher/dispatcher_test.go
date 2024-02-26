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
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

type testCase struct {
	Name          string
	ClientAddr    *net.UDPAddr
	DispAddr      *net.UDPAddr
	Pkt           *snet.Packet
	ExpectedValue bool
}

func testRunTestCase(t *testing.T, tc testCase) {
	serverConn, err := net.ListenUDP(tc.DispAddr.Network(), tc.DispAddr)
	require.NoError(t, err)
	defer serverConn.Close()
	setIPPktInfo(serverConn)
	emptyTopo := make(map[addr.Addr]netip.AddrPort)
	server := NewServer(emptyTopo, serverConn)

	clientConn, err := net.DialUDP("udp", tc.ClientAddr, tc.DispAddr)
	require.NoError(t, err)
	defer clientConn.Close()
	require.NoError(t, tc.Pkt.Serialize())
	_, err = clientConn.Write(tc.Pkt.Bytes)
	require.NoError(t, err)

	buf := make([]byte, 1024)
	oobuf := make([]byte, 1024)
	n, nn, _, nextHop, err := server.conn.ReadMsgUDPAddrPort(buf, oobuf)
	require.NoError(t, err)
	underlayAddr := server.parseUnderlayAddr(oobuf[:nn])
	require.NotNil(t, underlayAddr)
	_, dstAddr, err := server.processMsgNextHop(buf[:n], *underlayAddr, nextHop)
	assert.NoError(t, err)
	assert.Equal(t, tc.ExpectedValue, dstAddr != nil)
}

func TestValidateAddr(t *testing.T) {
	clientAddr := xtest.MustParseUDPAddr(t, "127.0.0.1:0")
	dispIPv4Addr := xtest.MustParseUDPAddr(t, "127.0.0.1:40032")
	clientIPv6Addr := xtest.MustParseUDPAddr(t, "[::1]:0")
	dispIPv6Addr := xtest.MustParseUDPAddr(t, "[::1]:40032")
	mappedDispIPv4Addr := &net.UDPAddr{
		IP:   dispIPv4Addr.IP.To16(),
		Port: 40032,
	}
	testCases := []testCase{
		{
			Name:       "valid UDP/IPv4",
			ClientAddr: clientAddr,
			DispAddr:   dispIPv4Addr,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:2"),
						Host: addr.HostIP(clientAddr.AddrPort().Addr()),
					},
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:1"),
						Host: addr.HostIP(dispIPv4Addr.AddrPort().Addr()),
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
			Name:       "invalid UDP/IPv4",
			ClientAddr: clientAddr,
			DispAddr:   dispIPv4Addr,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:2"),
						Host: addr.HostIP(clientAddr.AddrPort().Addr()),
					},
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:1"),
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
			Name:       "valid SCMP/IPv4",
			ClientAddr: clientAddr,
			DispAddr:   dispIPv4Addr,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:2"),
						Host: addr.HostIP(clientAddr.AddrPort().Addr()),
					},
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:1"),
						Host: addr.HostIP(dispIPv4Addr.AddrPort().Addr()),
					},
					Payload: snet.SCMPDestinationUnreachable{
						Payload: MustPack(snet.Packet{
							PacketInfo: snet.PacketInfo{
								Source: snet.SCIONAddress{
									IA:   xtest.MustParseIA("1-ff00:0:2"),
									Host: addr.HostIP(dispIPv4Addr.AddrPort().Addr()),
								},
								Destination: snet.SCIONAddress{
									IA:   xtest.MustParseIA("1-ff00:0:1"),
									Host: addr.HostIP(clientAddr.AddrPort().Addr()),
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
			Name:       "invalid SCMP/IPv4",
			ClientAddr: clientAddr,
			DispAddr:   dispIPv4Addr,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:2"),
						Host: addr.HostIP(clientAddr.AddrPort().Addr()),
					},
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:1"),
						Host: addr.MustParseHost("127.0.0.2"),
					},
					Payload: snet.SCMPDestinationUnreachable{
						Payload: MustPack(snet.Packet{
							PacketInfo: snet.PacketInfo{
								Source: snet.SCIONAddress{
									IA:   xtest.MustParseIA("1-ff00:0:2"),
									Host: addr.HostIP(dispIPv4Addr.AddrPort().Addr()),
								},
								Destination: snet.SCIONAddress{
									IA:   xtest.MustParseIA("1-ff00:0:1"),
									Host: addr.HostIP(clientAddr.AddrPort().Addr()),
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
			Name:       "valid UDP/IPv6",
			ClientAddr: clientIPv6Addr,
			DispAddr:   dispIPv6Addr,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:2"),
						Host: addr.HostIP(clientIPv6Addr.AddrPort().Addr()),
					},
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:1"),
						Host: addr.HostIP(dispIPv6Addr.AddrPort().Addr()),
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
			Name:       "invalid UDP/IPv6",
			ClientAddr: clientIPv6Addr,
			DispAddr:   dispIPv6Addr,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:2"),
						Host: addr.HostIP(clientAddr.AddrPort().Addr()),
					},
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:1"),
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
			Name:       "valid SCMP/IPv6",
			ClientAddr: clientIPv6Addr,
			DispAddr:   dispIPv6Addr,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:2"),
						Host: addr.HostIP(clientIPv6Addr.AddrPort().Addr()),
					},
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:1"),
						Host: addr.HostIP(dispIPv6Addr.AddrPort().Addr()),
					},
					Payload: snet.SCMPDestinationUnreachable{
						Payload: MustPack(snet.Packet{
							PacketInfo: snet.PacketInfo{
								Source: snet.SCIONAddress{
									IA:   xtest.MustParseIA("1-ff00:0:2"),
									Host: addr.HostIP(dispIPv6Addr.AddrPort().Addr()),
								},
								Destination: snet.SCIONAddress{
									IA:   xtest.MustParseIA("1-ff00:0:1"),
									Host: addr.HostIP(clientIPv6Addr.AddrPort().Addr()),
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
			Name:       "invalid SCMP/IPv6",
			ClientAddr: clientIPv6Addr,
			DispAddr:   dispIPv6Addr,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:2"),
						Host: addr.HostIP(clientIPv6Addr.AddrPort().Addr()),
					},
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:1"),
						Host: addr.MustParseHost("::2"),
					},
					Payload: snet.SCMPDestinationUnreachable{
						Payload: MustPack(snet.Packet{
							PacketInfo: snet.PacketInfo{
								Source: snet.SCIONAddress{
									IA:   xtest.MustParseIA("1-ff00:0:2"),
									Host: addr.HostIP(dispIPv6Addr.AddrPort().Addr()),
								},
								Destination: snet.SCIONAddress{
									IA:   xtest.MustParseIA("1-ff00:0:1"),
									Host: addr.HostIP(clientIPv6Addr.AddrPort().Addr()),
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
			Name:       "IPv4-mapped-IPv6 to IPv4",
			ClientAddr: clientAddr,
			DispAddr:   dispIPv4Addr,
			Pkt: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:2"),
						Host: addr.HostIP(clientAddr.AddrPort().Addr()),
					},
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:1"),
						Host: addr.HostIP(mappedDispIPv4Addr.AddrPort().Addr()),
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
