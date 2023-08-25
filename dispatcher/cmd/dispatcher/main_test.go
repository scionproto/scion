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

// import (
// 	"context"
// 	"fmt"
// 	"net"
// 	"net/netip"
// 	"testing"
// 	"time"

// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"

// 	"github.com/scionproto/scion/dispatcher"
// 	"github.com/scionproto/scion/pkg/addr"
// 	"github.com/scionproto/scion/pkg/private/xtest"
// 	"github.com/scionproto/scion/pkg/snet"
// 	"github.com/scionproto/scion/pkg/snet/path"
// )

// const (
// 	defaultTimeout      = 2 * time.Second
// 	defaultWaitDuration = 200 * time.Millisecond
// )

// type TestSettings struct {
// 	UnderlayPort int
// }

// func InitTestSettings(t *testing.T, dispatcherTestPort int) *TestSettings {
// 	return &TestSettings{
// 		UnderlayPort: dispatcherTestPort,
// 	}
// }

// type ClientAddress struct {
// 	IA              addr.IA
// 	PublicAddress   netip.Addr
// 	PublicPort      uint16
// 	ServiceAddress  addr.SVC
// 	UnderlayAddress *net.UDPAddr
// }

// type TestCase struct {
// 	Name            string
// 	ClientAddress   *ClientAddress
// 	TestPackets     []*snet.Packet
// 	UnderlayAddress *net.UDPAddr
// 	ExpectedPacket  *snet.Packet
// }

// func genTestCases(dispatcherPort int) []*TestCase {
// 	// Addressing information
// 	var (
// 		commonIA              = xtest.MustParseIA("1-ff00:0:1")
// 		commonPublicL3Address = netip.AddrFrom4([4]byte{127, 0, 0, 1})
// 		commonUnderlayAddress = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: dispatcherPort}
// 		clientXAddress        = &ClientAddress{
// 			IA:              commonIA,
// 			PublicAddress:   commonPublicL3Address,
// 			PublicPort:      8080,
// 			ServiceAddress:  addr.SvcNone,
// 			UnderlayAddress: commonUnderlayAddress,
// 		}
// 		clientYAddress = &ClientAddress{
// 			IA:              commonIA,
// 			PublicAddress:   commonPublicL3Address,
// 			PublicPort:      8081,
// 			ServiceAddress:  addr.SvcCS,
// 			UnderlayAddress: commonUnderlayAddress,
// 		}
// 	)

// 	var testCases = []*TestCase{
// 		{
// 			Name:          "UDP/IPv4 packet",
// 			ClientAddress: clientXAddress,
// 			TestPackets: []*snet.Packet{
// 				{
// 					PacketInfo: snet.PacketInfo{
// 						Source: snet.SCIONAddress{
// 							IA:   clientXAddress.IA,
// 							Host: addr.HostIP(clientXAddress.PublicAddress),
// 						},
// 						Destination: snet.SCIONAddress{
// 							IA:   clientXAddress.IA,
// 							Host: addr.HostIP(clientXAddress.PublicAddress),
// 						},
// 						Payload: snet.UDPPayload{
// 							SrcPort: clientXAddress.PublicPort,
// 							DstPort: clientXAddress.PublicPort,
// 							Payload: []byte{1, 2, 3, 4},
// 						},
// 						Path: path.Empty{},
// 					},
// 				},
// 			},
// 			UnderlayAddress: clientXAddress.UnderlayAddress,
// 			ExpectedPacket: &snet.Packet{
// 				PacketInfo: snet.PacketInfo{
// 					Source: snet.SCIONAddress{
// 						IA:   clientXAddress.IA,
// 						Host: addr.HostIP(clientXAddress.PublicAddress),
// 					},
// 					Destination: snet.SCIONAddress{
// 						IA:   clientXAddress.IA,
// 						Host: addr.HostIP(clientXAddress.PublicAddress),
// 					},
// 					Payload: snet.UDPPayload{
// 						SrcPort: clientXAddress.PublicPort,
// 						DstPort: clientXAddress.PublicPort,
// 						Payload: []byte{1, 2, 3, 4},
// 					},
// 					Path: snet.RawPath{},
// 				},
// 			},
// 		},
// 		{
// 			Name:          "UDP/SVC packet",
// 			ClientAddress: clientYAddress,
// 			TestPackets: []*snet.Packet{
// 				{
// 					PacketInfo: snet.PacketInfo{
// 						Source: snet.SCIONAddress{
// 							IA:   clientYAddress.IA,
// 							Host: addr.HostIP(clientYAddress.PublicAddress),
// 						},
// 						Destination: snet.SCIONAddress{
// 							IA:   clientYAddress.IA,
// 							Host: addr.HostSVC(clientYAddress.ServiceAddress),
// 						},
// 						Payload: snet.UDPPayload{
// 							SrcPort: clientYAddress.PublicPort,
// 							DstPort: clientYAddress.PublicPort,
// 							Payload: []byte{5, 6, 7, 8},
// 						},
// 						Path: path.Empty{},
// 					},
// 				},
// 			},
// 			UnderlayAddress: clientXAddress.UnderlayAddress,
// 			ExpectedPacket: &snet.Packet{
// 				PacketInfo: snet.PacketInfo{
// 					Source: snet.SCIONAddress{
// 						IA:   clientYAddress.IA,
// 						Host: addr.HostIP(clientYAddress.PublicAddress),
// 					},
// 					Destination: snet.SCIONAddress{
// 						IA:   clientYAddress.IA,
// 						Host: addr.HostSVC(clientYAddress.ServiceAddress),
// 					},
// 					Payload: snet.UDPPayload{
// 						SrcPort: clientYAddress.PublicPort,
// 						DstPort: clientYAddress.PublicPort,
// 						Payload: []byte{5, 6, 7, 8},
// 					},
// 					Path: snet.RawPath{},
// 				},
// 			},
// 		},
// 		{
// 			Name:            "SCMP::Error, UDP quote",
// 			ClientAddress:   clientXAddress,
// 			UnderlayAddress: clientXAddress.UnderlayAddress,
// 			TestPackets: []*snet.Packet{
// 				{
// 					PacketInfo: snet.PacketInfo{
// 						Source: snet.SCIONAddress{
// 							IA:   clientXAddress.IA,
// 							Host: addr.HostIP(clientXAddress.PublicAddress),
// 						},
// 						Destination: snet.SCIONAddress{
// 							IA:   clientXAddress.IA,
// 							Host: addr.HostIP(clientXAddress.PublicAddress),
// 						},
// 						Payload: snet.SCMPDestinationUnreachable{
// 							Payload: MustPack(snet.Packet{
// 								PacketInfo: snet.PacketInfo{
// 									Source: snet.SCIONAddress{
// 										IA:   clientXAddress.IA,
// 										Host: addr.HostIP(clientXAddress.PublicAddress),
// 									},
// 									Destination: snet.SCIONAddress{
// 										IA:   clientXAddress.IA,
// 										Host: addr.HostIP(clientXAddress.PublicAddress),
// 									},
// 									Payload: snet.UDPPayload{SrcPort: clientXAddress.PublicPort},
// 									Path:    path.Empty{},
// 								},
// 							}),
// 						},
// 						Path: path.Empty{},
// 					},
// 				},
// 			},
// 			ExpectedPacket: &snet.Packet{
// 				PacketInfo: snet.PacketInfo{
// 					Source: snet.SCIONAddress{
// 						IA:   clientXAddress.IA,
// 						Host: addr.HostIP(clientXAddress.PublicAddress),
// 					},
// 					Destination: snet.SCIONAddress{
// 						IA:   clientXAddress.IA,
// 						Host: addr.HostIP(clientXAddress.PublicAddress),
// 					},
// 					Payload: snet.SCMPDestinationUnreachable{
// 						Payload: MustPack(snet.Packet{
// 							PacketInfo: snet.PacketInfo{
// 								Source: snet.SCIONAddress{
// 									IA:   clientXAddress.IA,
// 									Host: addr.HostIP(clientXAddress.PublicAddress),
// 								},
// 								Destination: snet.SCIONAddress{
// 									IA:   clientXAddress.IA,
// 									Host: addr.HostIP(clientXAddress.PublicAddress),
// 								},
// 								Payload: snet.UDPPayload{SrcPort: clientXAddress.PublicPort},
// 								Path:    path.Empty{},
// 							},
// 						}),
// 					},
// 					Path: snet.RawPath{},
// 				},
// 			},
// 		},
// 		{
// 			Name:            "SCMP::Error, SCMP quote",
// 			ClientAddress:   clientXAddress,
// 			UnderlayAddress: clientXAddress.UnderlayAddress,
// 			TestPackets: []*snet.Packet{
// 				{
// 					// Force a SCMP General ID registration to happen, but route it
// 					// from nowhere so we don't get it back
// 					PacketInfo: snet.PacketInfo{
// 						Source: snet.SCIONAddress{
// 							IA:   xtest.MustParseIA("1-ff00:0:42"), // middle of nowhere
// 							Host: addr.HostIP(clientXAddress.PublicAddress),
// 						},
// 						Destination: snet.SCIONAddress{
// 							IA:   clientYAddress.IA,
// 							Host: addr.HostIP(clientYAddress.PublicAddress),
// 						},
// 						Payload: snet.SCMPEchoRequest{Identifier: 0xdead},
// 						Path:    path.Empty{},
// 					},
// 				},
// 				{
// 					PacketInfo: snet.PacketInfo{
// 						Source: snet.SCIONAddress{
// 							IA:   clientXAddress.IA,
// 							Host: addr.HostIP(clientXAddress.PublicAddress),
// 						},
// 						Destination: snet.SCIONAddress{
// 							IA:   clientXAddress.IA,
// 							Host: addr.HostIP(clientXAddress.PublicAddress),
// 						},
// 						Payload: snet.SCMPDestinationUnreachable{
// 							Payload: MustPack(snet.Packet{
// 								PacketInfo: snet.PacketInfo{
// 									Source: snet.SCIONAddress{
// 										IA:   clientXAddress.IA,
// 										Host: addr.HostIP(clientXAddress.PublicAddress),
// 									},
// 									Destination: snet.SCIONAddress{
// 										IA:   clientXAddress.IA,
// 										Host: addr.HostIP(clientXAddress.PublicAddress),
// 									},
// 									Payload: snet.SCMPEchoRequest{Identifier: 0xdead},
// 									Path:    path.Empty{},
// 								},
// 							}),
// 						},
// 						Path: path.Empty{},
// 					},
// 				},
// 			},
// 			ExpectedPacket: &snet.Packet{
// 				PacketInfo: snet.PacketInfo{
// 					Source: snet.SCIONAddress{
// 						IA:   clientXAddress.IA,
// 						Host: addr.HostIP(clientXAddress.PublicAddress),
// 					},
// 					Destination: snet.SCIONAddress{
// 						IA:   clientXAddress.IA,
// 						Host: addr.HostIP(clientXAddress.PublicAddress),
// 					},
// 					Payload: snet.SCMPDestinationUnreachable{
// 						Payload: MustPack(snet.Packet{
// 							PacketInfo: snet.PacketInfo{
// 								Source: snet.SCIONAddress{
// 									IA:   clientXAddress.IA,
// 									Host: addr.HostIP(clientXAddress.PublicAddress),
// 								},
// 								Destination: snet.SCIONAddress{
// 									IA:   clientXAddress.IA,
// 									Host: addr.HostIP(clientXAddress.PublicAddress),
// 								},
// 								Payload: snet.SCMPEchoRequest{Identifier: 0xdead},
// 								Path:    path.Empty{},
// 							},
// 						}),
// 					},
// 					Path: snet.RawPath{},
// 				},
// 			},
// 		},
// 		{
// 			Name:            "SCMP::General::EchoRequest",
// 			ClientAddress:   clientXAddress,
// 			UnderlayAddress: clientYAddress.UnderlayAddress,
// 			TestPackets: []*snet.Packet{
// 				{
// 					PacketInfo: snet.PacketInfo{
// 						Source: snet.SCIONAddress{
// 							IA:   clientXAddress.IA,
// 							Host: addr.HostIP(clientXAddress.PublicAddress),
// 						},
// 						Destination: snet.SCIONAddress{
// 							IA:   clientYAddress.IA,
// 							Host: addr.HostIP(clientYAddress.PublicAddress),
// 						},
// 						Payload: snet.SCMPEchoRequest{
// 							Identifier: 0xdead,
// 							SeqNumber:  0xcafe,
// 							Payload:    []byte("hello?"),
// 						},
// 						Path: path.Empty{},
// 					},
// 				},
// 			},
// 			ExpectedPacket: &snet.Packet{
// 				PacketInfo: snet.PacketInfo{
// 					Source: snet.SCIONAddress{
// 						IA:   clientYAddress.IA,
// 						Host: addr.HostIP(clientYAddress.PublicAddress),
// 					},
// 					Destination: snet.SCIONAddress{
// 						IA:   clientXAddress.IA,
// 						Host: addr.HostIP(clientXAddress.PublicAddress),
// 					},
// 					Payload: snet.SCMPEchoReply{
// 						Identifier: 0xdead,
// 						SeqNumber:  0xcafe,
// 						Payload:    []byte("hello?"),
// 					},
// 					Path: snet.RawPath{},
// 				},
// 			},
// 		},
// 		{
// 			Name:            "SCMP::General::TraceRouteRequest",
// 			ClientAddress:   clientXAddress,
// 			UnderlayAddress: clientYAddress.UnderlayAddress,
// 			TestPackets: []*snet.Packet{
// 				{
// 					PacketInfo: snet.PacketInfo{
// 						Source: snet.SCIONAddress{
// 							IA:   clientXAddress.IA,
// 							Host: addr.HostIP(clientXAddress.PublicAddress),
// 						},
// 						Destination: snet.SCIONAddress{
// 							IA:   clientYAddress.IA,
// 							Host: addr.HostIP(clientYAddress.PublicAddress),
// 						},
// 						Payload: snet.SCMPTracerouteRequest{Identifier: 0xdeaf, Sequence: 0xcafd},
// 						Path:    path.Empty{},
// 					},
// 				},
// 			},
// 			ExpectedPacket: &snet.Packet{
// 				PacketInfo: snet.PacketInfo{
// 					Source: snet.SCIONAddress{
// 						IA:   clientYAddress.IA,
// 						Host: addr.HostIP(clientYAddress.PublicAddress),
// 					},
// 					Destination: snet.SCIONAddress{
// 						IA:   clientXAddress.IA,
// 						Host: addr.HostIP(clientXAddress.PublicAddress),
// 					},
// 					Payload: snet.SCMPTracerouteReply{Identifier: 0xdeaf, Sequence: 0xcafd},
// 					Path:    snet.RawPath{},
// 				},
// 			},
// 		},
// 	}
// 	return testCases
// }

// func TestDataplaneIntegration(t *testing.T) {
// 	dispatcherTestPort := 40032
// 	settings := InitTestSettings(t, dispatcherTestPort)

// 	go func() {
// 		err := RunDispatcher(dispatcherTestPort)
// 		require.NoError(t, err, "dispatcher error")
// 	}()
// 	time.Sleep(defaultWaitDuration)

// 	testCases := genTestCases(dispatcherTestPort)
// 	for _, tc := range testCases {
// 		t.Run(tc.Name, func(t *testing.T) {
// 			RunTestCase(t, tc, settings)
// 		})
// 		time.Sleep(defaultWaitDuration)
// 	}
// }

// func RunTestCase(t *testing.T, tc *TestCase, settings *TestSettings) {
// 	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", settings.UnderlayPort))
// 	require.NoError(t, err)
// 	dispatcherService := dispatcher.NewServer(localAddr)
// 	ctx, cancelF := context.WithTimeout(context.Background(), defaultTimeout)
// 	defer cancelF()
// 	conn, _, err := dispatcherService.Register(
// 		ctx,
// 		tc.ClientAddress.IA,
// 		&net.UDPAddr{
// 			IP:   tc.ClientAddress.PublicAddress.AsSlice(),
// 			Port: int(tc.ClientAddress.PublicPort),
// 		},
// 		tc.ClientAddress.ServiceAddress,
// 	)
// 	require.NoError(t, err, "unable to open socket")
// 	// Always destroy the connection s.t. future tests aren't compromised by a
// 	// fatal in this subtest
// 	defer conn.Close()

// 	for _, packet := range tc.TestPackets {
// 		require.NoError(t, packet.Serialize())
// 		fmt.Printf("sending packet: %x\n", packet.Bytes)
// 		_, err = conn.WriteTo(packet.Bytes, tc.UnderlayAddress)
// 		require.NoError(t, err, "unable to write message")
// 	}

// 	err = conn.SetReadDeadline(time.Now().Add(defaultTimeout))
// 	require.NoError(t, err, "unable to set read deadline")

// 	rcvPkt := snet.Packet{}
// 	rcvPkt.Prepare()
// 	n, _, err := conn.ReadFrom(rcvPkt.Bytes)
// 	require.NoError(t, err, "unable to read message")
// 	rcvPkt.Bytes = rcvPkt.Bytes[:n]

// 	require.NoError(t, rcvPkt.Decode())

// 	err = conn.Close()
// 	require.NoError(t, err, "unable to close conn")

// 	assert.Equal(t, tc.ExpectedPacket.PacketInfo, rcvPkt.PacketInfo)
// }

// func MustPack(pkt snet.Packet) []byte {
// 	if err := pkt.Serialize(); err != nil {
// 		panic(err)
// 	}
// 	return pkt.Bytes
// }
