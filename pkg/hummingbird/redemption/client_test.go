// Copyright 2026 ETH Zurich
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

package redemption

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/mock_daemon"
	"github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/log"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	hbirdv1connect "github.com/scionproto/scion/pkg/proto/hbird/v1/hbirdconnect"
	"github.com/scionproto/scion/pkg/segment/iface"
	hummlib "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/keyconf"
)

// TestSupportsHumm checks that the note parser recognizes the minimal
// Hummingbird capability advertisement in the path metadata JSON blob.
func TestSupportsHumm(t *testing.T) {
	example := `
	{
			"hummingbird-v0": {
					"supported": true,
					"min-cost": 102,
					"min-bw": 14,
					"max-bw": 14,
					"markets": {
							"market1": "https://example.com/api/v0/info",
							"market2": "https://www.example.net/info",
							"brokerA": "https://example.org/api/v0/exchange"
					}
			}
	}`
	got := supportsHumm(example)
	require.True(t, got)
}

// TestRedeemHopWithPreviousRequestNoRequest checks the early-return case:
// build a hermetic client with an empty request map, redeem one hop, and
// verify that the method reports "nothing to do" as nil, nil.
func TestRedeemHopWithPreviousRequestNoRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	sdConn := mock_daemon.NewMockConnector(ctrl)
	c, _, _, _ := newHermeticClient(t, sdConn)

	hop, err := c.RedeemHopWithPreviousRequest(context.Background(), testLocalIA())
	require.NoError(t, err)
	require.Nil(t, hop)
}

// TestRedeemHopIntraAS exercises the local-AS redemption path.
// Steps:
//  1. Build a hermetic client with fake intra- and inter-AS RPC clients.
//  2. Store one request for the local IA.
//  3. Redeem that hop and verify the returned flyover fields.
//  4. Check that only the intra-AS client was used and that the protobuf
//     request carried the expected client key, bandwidth, interfaces, and tokens.
func TestRedeemHopIntraAS(t *testing.T) {
	ctrl := gomock.NewController(t)
	sdConn := mock_daemon.NewMockConnector(ctrl)
	c, intraClient, interClient, interCalls := newHermeticClient(t, sdConn)

	req := hummingbird.RedemptionRequest{
		RedemptionRequestNoHop: hummingbird.RedemptionRequestNoHop{
			Bw:           1,
			StartTime:    1,
			Duration:     5,
			IngressToken: []byte("ingress-token"),
			EgressToken:  []byte("egress-token"),
		},
		Ingress: 0,
		Egress:  41,
	}
	c.SetRequestDataForLaterRedemption(testLocalIA(), req)

	hop, err := c.RedeemHopWithPreviousRequest(context.Background(), testLocalIA())
	require.NoError(t, err)
	require.NotNil(t, hop)
	require.Equal(t, uint32(1001), hop.Flyover.ResID)
	require.Len(t, hop.Flyover.Ak, hummingbird.AkSize)
	require.Equal(t, testLocalIA(), hop.IA)
	require.Equal(t, req.Ingress, hop.Ingress)
	require.Equal(t, req.Egress, hop.Egress)
	require.Equal(t, req.Bw, hop.Flyover.Bw)
	require.Equal(t, req.StartTime, hop.Flyover.StartTime)
	require.Equal(t, req.Duration, hop.Flyover.Duration)
	require.Equal(t, 1, intraClient.RedeemCalls())
	require.Equal(t, 0, interClient.RedeemCalls())
	require.Empty(t, interCalls.Addrs())

	gotReq := intraClient.LastRedeemRequest()
	require.NotNil(t, gotReq)
	require.Equal(t, c.pubBytes, gotReq.ClientKey)
	require.Len(t, gotReq.Redemption, 1)
	require.Equal(t, uint32(req.Ingress), gotReq.Redemption[0].RedInfo.Ingress)
	require.Equal(t, uint32(req.Egress), gotReq.Redemption[0].RedInfo.Egress)
	require.Equal(t, uint32(req.Bw), gotReq.Redemption[0].RedInfo.Bw)
	require.Equal(t, req.StartTime, gotReq.Redemption[0].RedInfo.StartTime)
	require.Equal(t, uint32(req.Duration), gotReq.Redemption[0].RedInfo.Duration)
	require.Equal(t, req.IngressToken, gotReq.Redemption[0].IngressToken)
	require.Equal(t, req.EgressToken, gotReq.Redemption[0].EgressToken)
}

// TestRedeemHopInterAS exercises the remote-AS redemption path.
// Steps:
//  1. Mock daemon path lookup for the destination AS.
//  2. Store one request for that remote IA.
//  3. Redeem the hop and verify the flyover result.
//  4. Check that only the inter-AS client was used and that the constructed
//     destination UDP address points at the redemption server port and the
//     mocked discovery IP.
func TestRedeemHopInterAS(t *testing.T) {
	ctrl := gomock.NewController(t)
	sdConn := mock_daemon.NewMockConnector(ctrl)
	c, intraClient, interClient, interCalls := newHermeticClient(t, sdConn)
	dstIA := testTransitIA()
	pathToDst := tinyPathTo110()
	sdConn.EXPECT().Paths(gomock.Any(), dstIA, testLocalIA(), types.PathReqFlags{}).
		Return([]snet.Path{pathToDst}, nil)

	req := hummingbird.RedemptionRequest{
		RedemptionRequestNoHop: hummingbird.RedemptionRequestNoHop{
			Bw:        1,
			StartTime: 1,
			Duration:  5,
		},
		Ingress: 0,
		Egress:  41,
	}
	c.SetRequestDataForLaterRedemption(dstIA, req)

	hop, err := c.RedeemHopWithPreviousRequest(context.Background(), dstIA)
	require.NoError(t, err)
	require.NotNil(t, hop)
	require.Equal(t, uint32(2002), hop.Flyover.ResID)
	require.Len(t, hop.Flyover.Ak, hummingbird.AkSize)
	require.Equal(t, dstIA, hop.IA)
	require.Equal(t, req.Ingress, hop.Ingress)
	require.Equal(t, req.Egress, hop.Egress)
	require.Equal(t, req.Bw, hop.Flyover.Bw)
	require.Equal(t, req.StartTime, hop.Flyover.StartTime)
	require.Equal(t, req.Duration, hop.Flyover.Duration)
	require.Equal(t, 0, intraClient.RedeemCalls())
	require.Equal(t, 1, interClient.RedeemCalls())

	addrs := interCalls.Addrs()
	require.Len(t, addrs, 1)
	require.Equal(t, dstIA, addrs[0].IA)
	require.Equal(t, net.IP(netip.MustParseAddr("10.0.0.110").AsSlice()), addrs[0].Host.IP)
	require.Equal(t, RedemptionServerPort, addrs[0].Host.Port)
	require.Equal(t, pathToDst.UnderlayNextHop(), addrs[0].NextHop)

	gotReq := interClient.LastRedeemRequest()
	require.NotNil(t, gotReq)
	require.Equal(t, c.pubBytes, gotReq.ClientKey)
}

// TestRedeemPath checks whole-path redemption using pre-stored per-AS requests.
// It first verifies the empty-request case, where all hop results stay nil, and
// then populates requests for all ASes on the synthetic tiny path and confirms
// that redemption preserves hop order and interface mapping.
func TestRedeemPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	sdConn := mock_daemon.NewMockConnector(ctrl)
	c, intraClient, interClient, _ := newHermeticClient(t, sdConn)
	chosenPath := tinyPathTo112()

	sdConn.EXPECT().Paths(gomock.Any(), testTransitIA(), testLocalIA(), types.PathReqFlags{}).
		Return([]snet.Path{tinyPathTo110()}, nil).AnyTimes()
	sdConn.EXPECT().Paths(gomock.Any(), testDstIA(), testLocalIA(), types.PathReqFlags{}).
		Return([]snet.Path{tinyPathTo112()}, nil).AnyTimes()

	results, err := c.RedeemPathWithPreviousRequests(context.Background(), chosenPath)
	require.NoError(t, err)
	require.Len(t, results, 3)
	require.Nil(t, results[0])
	require.Nil(t, results[1])
	require.Nil(t, results[2])

	request := hummingbird.RedemptionRequest{
		RedemptionRequestNoHop: hummingbird.RedemptionRequestNoHop{
			Bw:        1,
			StartTime: 1,
			Duration:  5,
		},
	}
	request.Ingress = 0
	request.Egress = 41
	c.SetRequestDataForLaterRedemption(testLocalIA(), request)
	request.Ingress = 1
	request.Egress = 2
	c.SetRequestDataForLaterRedemption(testTransitIA(), request)
	request.Ingress = 1
	request.Egress = 0
	c.SetRequestDataForLaterRedemption(testDstIA(), request)

	require.Len(t, c.requestMap, 3)

	results, err = c.RedeemPathWithPreviousRequests(context.Background(), chosenPath)
	require.NoError(t, err)
	require.Len(t, results, 3)
	checkHop(t, results[0], testLocalIA(), 0, 41, 1, 5)
	checkHop(t, results[1], testTransitIA(), 1, 2, 1, 5)
	checkHop(t, results[2], testDstIA(), 1, 0, 1, 5)
	require.Equal(t, 1, intraClient.RedeemCalls())
	require.Equal(t, 2, interClient.RedeemCalls())
}

// TestRedeemPathWithRequest checks the convenience path API that derives
// per-hop requests from one common request payload.
// The test starts with stale request-map content, calls RedeemPathWithRequest,
// and then verifies both the redeemed hops and that the request map was
// replaced with the path-derived ingress/egress tuples.
func TestRedeemPathWithRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	sdConn := mock_daemon.NewMockConnector(ctrl)
	c, intraClient, interClient, _ := newHermeticClient(t, sdConn)
	chosenPath := tinyPathTo112()

	sdConn.EXPECT().Paths(gomock.Any(), testTransitIA(), testLocalIA(), types.PathReqFlags{}).
		Return([]snet.Path{tinyPathTo110()}, nil).AnyTimes()
	sdConn.EXPECT().Paths(gomock.Any(), testDstIA(), testLocalIA(), types.PathReqFlags{}).
		Return([]snet.Path{tinyPathTo112()}, nil).AnyTimes()

	c.requestMap[testLocalIA()] = hummingbird.RedemptionRequest{
		RedemptionRequestNoHop: hummingbird.RedemptionRequestNoHop{
			Bw:        99,
			StartTime: 99,
			Duration:  99,
		},
		Ingress: 9,
		Egress:  9,
	}

	request := hummingbird.RedemptionRequestNoHop{
		Bw:        1,
		StartTime: 1,
		Duration:  5,
	}
	results, err := c.RedeemPathWithRequest(context.Background(), chosenPath, request)
	require.NoError(t, err)
	require.Len(t, results, 3)
	checkHop(t, results[0], testLocalIA(), 0, 41, 1, 5)
	checkHop(t, results[1], testTransitIA(), 1, 2, 1, 5)
	checkHop(t, results[2], testDstIA(), 1, 0, 1, 5)
	require.Equal(t, 1, intraClient.RedeemCalls())
	require.Equal(t, 2, interClient.RedeemCalls())

	require.Len(t, c.requestMap, 3)
	require.Equal(t, request.Bw, c.requestMap[testLocalIA()].Bw)
	require.Equal(t, uint16(0), c.requestMap[testLocalIA()].Ingress)
	require.Equal(t, uint16(41), c.requestMap[testLocalIA()].Egress)
	require.Equal(t, uint16(1), c.requestMap[testTransitIA()].Ingress)
	require.Equal(t, uint16(2), c.requestMap[testTransitIA()].Egress)
	require.Equal(t, uint16(1), c.requestMap[testDstIA()].Ingress)
	require.Equal(t, uint16(0), c.requestMap[testDstIA()].Egress)
}

// TestAkCorrectness checks the crypto contract of redeemHop without a live
// server. It derives the expected Ak from test master keys, makes the fake
// server encrypt exactly that Ak to the client's public key, and then verifies
// that the client decrypts the response back to the expected value.
func TestAkCorrectness(t *testing.T) {
	ctrl := gomock.NewController(t)
	sdConn := mock_daemon.NewMockConnector(ctrl)
	c, _, _, _ := newHermeticClient(t, sdConn)
	req := hummingbird.RedemptionRequest{
		RedemptionRequestNoHop: hummingbird.RedemptionRequestNoHop{
			Bw:        1,
			StartTime: 1,
			Duration:  5,
		},
		Ingress: 0,
		Egress:  41,
	}
	resID := uint32(777)
	expectedHop := &path.Hop{
		BaseHop: path.BaseHop{
			IA:      testLocalIA(),
			Ingress: req.Ingress,
			Egress:  req.Egress,
		},
		Flyover: &path.FlyoverData{
			ResID:     resID,
			Bw:        req.Bw,
			StartTime: req.StartTime,
			Duration:  req.Duration,
		},
	}
	expectedAk := deriveAk(t, testLocalIA(), expectedHop)

	c.intraAsClientFactory = func() hbirdv1connect.HBirdServiceClient {
		return newRedeemClient(func(reqMsg *hbirdv1.RedemptionRequests) (*hbirdv1.RedemptionResponses, error) {
			encryptedAk, err := encryptForClientKey(reqMsg.ClientKey, expectedAk[:])
			if err != nil {
				return nil, err
			}
			return &hbirdv1.RedemptionResponses{
				Reservation: []*hbirdv1.Reservation{{
					ResId:   resID,
					AuthKey: encryptedAk,
				}},
			}, nil
		})
	}

	c.SetRequestDataForLaterRedemption(testLocalIA(), req)
	flyover, err := c.RedeemHopWithPreviousRequest(context.Background(), testLocalIA())
	require.NoError(t, err)
	require.Equal(t, expectedAk, flyover.Flyover.Ak)
}

// TestClientForAsChoosesByLocalIA checks the routing decision inside clientForAs:
// local IA must use the intra-AS client directly, while a remote IA must trigger
// path lookup and use the inter-AS client factory.
func TestClientForAsChoosesByLocalIA(t *testing.T) {
	ctrl := gomock.NewController(t)
	sdConn := mock_daemon.NewMockConnector(ctrl)
	c, intraClient, interClient, interCalls := newHermeticClient(t, sdConn)
	sdConn.EXPECT().Paths(gomock.Any(), testTransitIA(), testLocalIA(), types.PathReqFlags{}).
		Return([]snet.Path{tinyPathTo110()}, nil)

	localClient, err := c.clientForAs(context.Background(), testLocalIA())
	require.NoError(t, err)
	require.Same(t, intraClient, localClient)

	remoteClient, err := c.clientForAs(context.Background(), testTransitIA())
	require.NoError(t, err)
	require.Same(t, interClient, remoteClient)
	require.Len(t, interCalls.Addrs(), 1)
	require.Equal(t, testTransitIA(), interCalls.Addrs()[0].IA)
}

// TestGetDstAddrUsesFirstPath checks that getDstAddr selects the first daemon
// path result and combines that path's discovery information and next hop into
// the UDP address used for remote redemption.
func TestGetDstAddrUsesFirstPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	sdConn := mock_daemon.NewMockConnector(ctrl)
	c, _, _, _ := newHermeticClient(t, sdConn)
	first := tinyPathTo110()
	second := path.Path{
		Src:     testLocalIA(),
		Dst:     testTransitIA(),
		NextHop: &net.UDPAddr{IP: net.IP(netip.MustParseAddr("192.0.2.2").AsSlice()), Port: 31000},
		Meta: snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: testLocalIA(), ID: iface.ID(41)},
				{IA: testTransitIA(), ID: iface.ID(1)},
			},
			DiscoveryInformation: map[addr.IA]snet.DiscoveryInformation{
				testTransitIA(): snet.DiscoveryInformation{
					ControlServices: []netip.AddrPort{
						netip.MustParseAddrPort("10.0.0.111:30255"),
					},
				},
			},
		},
	}
	sdConn.EXPECT().Paths(gomock.Any(), testTransitIA(), testLocalIA(), types.PathReqFlags{}).
		Return([]snet.Path{first, second}, nil)

	dstAddr, err := c.getDstAddr(context.Background(), testTransitIA())
	require.NoError(t, err)
	require.Equal(t, testTransitIA(), dstAddr.IA)
	require.Equal(t, net.IP(netip.MustParseAddr("10.0.0.110").AsSlice()), dstAddr.Host.IP)
	require.Equal(t, RedemptionServerPort, dstAddr.Host.Port)
	require.Equal(t, first.UnderlayNextHop(), dstAddr.NextHop)
}

// TestGetDstAddrErrorsWhenNoPathReturned checks the defensive error path where
// the daemon returns no candidate path for the requested destination IA.
func TestGetDstAddrErrorsWhenNoPathReturned(t *testing.T) {
	ctrl := gomock.NewController(t)
	sdConn := mock_daemon.NewMockConnector(ctrl)
	c, _, _, _ := newHermeticClient(t, sdConn)
	sdConn.EXPECT().Paths(gomock.Any(), testTransitIA(), testLocalIA(), types.PathReqFlags{}).
		Return(nil, nil)

	dstAddr, err := c.getDstAddr(context.Background(), testTransitIA())
	require.Nil(t, dstAddr)
	require.ErrorContains(t, err, "no path available")
}

// TestRedeemHopErrors checks the main failure modes of redeemHop:
// RPC failure, nil response, empty reservation list, and a decrypted Ak with
// the wrong length.
func TestRedeemHopErrors(t *testing.T) {
	c, _, _, _ := newHermeticClient(t, nil)
	req := hummingbird.RedemptionRequest{
		RedemptionRequestNoHop: hummingbird.RedemptionRequestNoHop{
			Bw:        1,
			StartTime: 1,
			Duration:  5,
		},
		Ingress: 1,
		Egress:  2,
	}

	testCases := map[string]struct {
		client  hbirdv1connect.HBirdServiceClient
		wantErr string
	}{
		"client error": {
			client: newRedeemClient(func(*hbirdv1.RedemptionRequests) (*hbirdv1.RedemptionResponses, error) {
				return nil, errors.New("boom")
			}),
			wantErr: "redeem call failed",
		},
		"nil response": {
			client: &fakeHBirdServiceClient{
				redeemFn: func(context.Context, *connect.Request[hbirdv1.RedemptionRequests]) (*connect.Response[hbirdv1.RedemptionResponses], error) {
					return nil, nil
				},
			},
			wantErr: "redemption response is nil",
		},
		"empty reservation": {
			client: newRedeemClient(func(*hbirdv1.RedemptionRequests) (*hbirdv1.RedemptionResponses, error) {
				return &hbirdv1.RedemptionResponses{}, nil
			}),
			wantErr: "redemption call returned no flyovers",
		},
		"wrong ak length": {
			client: newRedeemClient(func(reqMsg *hbirdv1.RedemptionRequests) (*hbirdv1.RedemptionResponses, error) {
				encryptedAk, err := encryptForClientKey(reqMsg.ClientKey, []byte("bad"))
				if err != nil {
					return nil, err
				}
				return &hbirdv1.RedemptionResponses{
					Reservation: []*hbirdv1.Reservation{{
						ResId:   1,
						AuthKey: encryptedAk,
					}},
				}, nil
			}),
			wantErr: "wrong length",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			hop, err := c.redeemHop(context.Background(), testTransitIA(), tc.client, req)
			require.Nil(t, hop)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// checkHop is a compact assertion helper for the successful path-redemption
// tests. It verifies the hop identity and the flyover fields that should be
// preserved from the request.
func checkHop(
	t *testing.T,
	hop *path.Hop,
	ia addr.IA,
	ingress uint16,
	egress uint16,
	bw uint16,
	duration uint16,
) {
	t.Helper()
	require.NotNil(t, hop)
	require.NotNil(t, hop.Flyover)
	require.Equal(t, ia, hop.IA)
	require.Equal(t, ingress, hop.Ingress)
	require.Equal(t, egress, hop.Egress)
	require.Equal(t, bw, hop.Flyover.Bw)
	require.Equal(t, uint32(1), hop.Flyover.StartTime)
	require.Equal(t, duration, hop.Flyover.Duration)
}

// newHermeticClient builds a RedemptionClient that never touches a live daemon
// or redemption server unless the caller explicitly wires one in via sdConn.
// It injects deterministic RSA keys, fake RPC clients, and a recorder for
// inter-AS client factory calls so that tests can inspect behavior precisely.
func newHermeticClient(
	t *testing.T,
	sdConn daemon.Connector,
) (*RedemptionClient, *fakeHBirdServiceClient, *fakeHBirdServiceClient, *interFactoryRecorder) {
	t.Helper()

	privKey := rsaPrivateKeyForTests(t)
	intraClient := newRedeemClient(successfulRedeemFunc(1001))
	interClient := newRedeemClient(successfulRedeemFunc(2002))
	interCalls := &interFactoryRecorder{}

	return &RedemptionClient{
		LocaIA:     testLocalIA(),
		SdConn:     sdConn,
		requestMap: make(hummingbird.RequestMap),
		intraAsClientFactory: func() hbirdv1connect.HBirdServiceClient {
			return intraClient
		},
		interAsClientFactory: func(
			_ context.Context,
			dst *snet.UDPAddr,
		) hbirdv1connect.HBirdServiceClient {
			interCalls.Add(dst)
			return interClient
		},
		pubBytes: x509.MarshalPKCS1PublicKey(&privKey.PublicKey),
		privKey:  privKey,
	}, intraClient, interClient, interCalls
}

// successfulRedeemFunc returns a fake Redeem implementation that always
// produces one reservation with the provided reservation ID and a deterministic
// Ak encrypted to the client's public key from the request.
func successfulRedeemFunc(
	resID uint32,
) func(*hbirdv1.RedemptionRequests) (*hbirdv1.RedemptionResponses, error) {
	return func(reqMsg *hbirdv1.RedemptionRequests) (*hbirdv1.RedemptionResponses, error) {
		plaintextAk := make([]byte, hummingbird.AkSize)
		for i := range plaintextAk {
			plaintextAk[i] = byte(i + 1)
		}
		encryptedAk, err := encryptForClientKey(reqMsg.ClientKey, plaintextAk)
		if err != nil {
			return nil, err
		}
		return &hbirdv1.RedemptionResponses{
			Reservation: []*hbirdv1.Reservation{{
				ResId:   resID,
				AuthKey: encryptedAk,
			}},
		}, nil
	}
}

// newRedeemClient adapts a simple response-building function into the generated
// Connect client interface used by RedemptionClient.
func newRedeemClient(
	fn func(*hbirdv1.RedemptionRequests) (*hbirdv1.RedemptionResponses, error),
) *fakeHBirdServiceClient {
	return &fakeHBirdServiceClient{
		redeemFn: func(
			_ context.Context,
			req *connect.Request[hbirdv1.RedemptionRequests],
		) (*connect.Response[hbirdv1.RedemptionResponses], error) {
			resp, err := fn(req.Msg)
			if err != nil {
				return nil, err
			}
			return connect.NewResponse(resp), nil
		},
	}
}

// fakeHBirdServiceClient is a lightweight in-memory implementation of the
// generated HBirdService client interface. Besides returning synthetic replies,
// it records Redeem requests so tests can assert what the client sent.
type fakeHBirdServiceClient struct {
	mu         sync.Mutex
	redeemFn   func(context.Context, *connect.Request[hbirdv1.RedemptionRequests]) (*connect.Response[hbirdv1.RedemptionResponses], error)
	redeemReqs []*hbirdv1.RedemptionRequests
}

// Redeem records the outgoing request and delegates to the configured fake
// behavior.
func (f *fakeHBirdServiceClient) Redeem(
	ctx context.Context,
	req *connect.Request[hbirdv1.RedemptionRequests],
) (*connect.Response[hbirdv1.RedemptionResponses], error) {
	f.mu.Lock()
	if req != nil {
		f.redeemReqs = append(f.redeemReqs, req.Msg)
	}
	f.mu.Unlock()
	return f.redeemFn(ctx, req)
}

// Status satisfies the generated client interface; the redemption tests do not
// assert on this RPC.
func (f *fakeHBirdServiceClient) Status(
	context.Context,
	*connect.Request[emptypb.Empty],
) (*connect.Response[hbirdv1.StatusResponse], error) {
	return connect.NewResponse(&hbirdv1.StatusResponse{}), nil
}

// RedeemCalls returns how many Redeem RPCs this fake client has observed.
func (f *fakeHBirdServiceClient) RedeemCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.redeemReqs)
}

// LastRedeemRequest returns the most recent recorded Redeem protobuf payload.
func (f *fakeHBirdServiceClient) LastRedeemRequest() *hbirdv1.RedemptionRequests {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.redeemReqs) == 0 {
		return nil
	}
	return f.redeemReqs[len(f.redeemReqs)-1]
}

// interFactoryRecorder records the destination addresses passed to the fake
// inter-AS client factory so tests can assert how remote redemptions were
// targeted.
type interFactoryRecorder struct {
	mu    sync.Mutex
	addrs []*snet.UDPAddr
}

// Add appends one destination address observed by the inter-AS client factory.
func (r *interFactoryRecorder) Add(dst *snet.UDPAddr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addrs = append(r.addrs, dst)
}

// Addrs returns a shallow copy of the recorded destination addresses.
func (r *interFactoryRecorder) Addrs() []*snet.UDPAddr {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*snet.UDPAddr, len(r.addrs))
	copy(out, r.addrs)
	return out
}

// encryptForClientKey encrypts plaintext using the RSA public key carried in
// the redemption request, mirroring what a real redemption server would do when
// returning an encrypted authentication key.
func encryptForClientKey(clientKey []byte, plaintext []byte) ([]byte, error) {
	pubKey, err := x509.ParsePKCS1PublicKey(clientKey)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
}

// tinyPathTo110 returns an in-memory path matching the first leg of the tiny
// topology from AS 111 to AS 110, including discovery information for the
// destination control service.
func tinyPathTo110() path.Path {
	return path.Path{
		Src:     testLocalIA(),
		Dst:     testTransitIA(),
		NextHop: &net.UDPAddr{IP: net.IP(netip.MustParseAddr("192.0.2.10").AsSlice()), Port: 30041},
		Meta: snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: testLocalIA(), ID: iface.ID(41)},
				{IA: testTransitIA(), ID: iface.ID(1)},
			},
			DiscoveryInformation: map[addr.IA]snet.DiscoveryInformation{
				testTransitIA(): snet.DiscoveryInformation{
					ControlServices: []netip.AddrPort{
						netip.MustParseAddrPort("10.0.0.110:30255"),
					},
				},
			},
		},
	}
}

// tinyPathTo112 returns an in-memory three-AS path matching the tiny-topology
// sequence 111 -> 110 -> 112. Tests use it to exercise hop extraction and
// per-hop redemption logic without requiring a running daemon.
func tinyPathTo112() path.Path {
	return path.Path{
		Src:     testLocalIA(),
		Dst:     testDstIA(),
		NextHop: &net.UDPAddr{IP: net.IP(netip.MustParseAddr("192.0.2.12").AsSlice()), Port: 30041},
		Meta: snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: testLocalIA(), ID: iface.ID(41)},
				{IA: testTransitIA(), ID: iface.ID(1)},
				{IA: testTransitIA(), ID: iface.ID(2)},
				{IA: testDstIA(), ID: iface.ID(1)},
			},
			DiscoveryInformation: map[addr.IA]snet.DiscoveryInformation{
				testDstIA(): snet.DiscoveryInformation{
					ControlServices: []netip.AddrPort{
						netip.MustParseAddrPort("10.0.0.112:30255"),
					},
				},
			},
		},
	}
}

// testLocalIA returns the fixed local IA used throughout the hermetic tests.
func testLocalIA() addr.IA {
	return addr.MustParseIA("1-ff00:0:111")
}

// testTransitIA returns the fixed middle AS used throughout the hermetic tests.
func testTransitIA() addr.IA {
	return addr.MustParseIA("1-ff00:0:110")
}

// testDstIA returns the fixed remote destination IA used throughout the
// hermetic path tests.
func testDstIA() addr.IA {
	return addr.MustParseIA("1-ff00:0:112")
}

// deriveAk derives the expected Hummingbird authentication key using the master secret in
// the keys directory of the ia AS.
func deriveAk(t *testing.T, ia addr.IA, flyover *path.Hop) [hummingbird.AkSize]byte {
	t.Helper()

	keysDir := filepath.Join(
		"testdata",
		addr.FormatAS(ia.AS(), addr.WithDefaultPrefix(), addr.WithFileSeparator()),
		"keys",
	)
	t.Logf("keysDir = %s", keysDir)
	master, err := keyconf.LoadMaster(keysDir)
	require.NoError(t, err)
	log.Debug("Have Hummingbird master secret for IA", "ia", ia)
	sv := hummlib.DeriveSecretValue(master.Key0)
	t.Logf("sv = %s", hex.EncodeToString(sv))

	block, err := aes.NewCipher(sv)
	require.NoError(t, err)
	buffer := make([]byte, hummlib.AkBufferSize)

	t.Logf("resID = %d, bw = %d, in = %d, eg = %d, start = %d, dur = %d",
		flyover.Flyover.ResID,
		flyover.Flyover.Bw,
		flyover.Ingress,
		flyover.Egress,
		flyover.Flyover.StartTime,
		flyover.Flyover.Duration,
	)
	akRaw := hummlib.DeriveAuthKey(
		block,
		flyover.Flyover.ResID,
		flyover.Flyover.Bw,
		flyover.Ingress,
		flyover.Egress,
		flyover.Flyover.StartTime,
		flyover.Flyover.Duration,
		buffer,
	)
	t.Logf("ak = %s", hex.EncodeToString(akRaw))
	var ak [hummingbird.AkSize]byte
	copy(ak[:], akRaw)

	return ak
}

// rsaPrivateKeyForTests returns the deterministic RSA private key used by the
// hermetic redemption tests. Using a fixed key keeps encrypted Ak generation
// and request payload assertions stable across runs.
func rsaPrivateKeyForTests(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	const testClientPrivateKey = "MIICXQIBAAKBgQC1zb0DLTfmFFcZRd5RFo/S" +
		"EVhGMuO+KLgexCeiVJMxnbvfkE4cqR3zp2WsTuG24A97JeVAiglw4FvDA9X7kKCjRFam4JVYq3RAJ7" +
		"NcCX6leVD/fasRldiMIEuoo9oa8egu/pc7S/mu8hjcg1kxJzJYz7YElA4JNOpJNtb2beWToQIDAQAB" +
		"AoGBAKAUejuT00aJ3m9ob+rifNyxXRLiuFm2LPkaKvPqmHj1tHmT7NObrb3fRc1E38ZQ4BDFO2lqog" +
		"l75BCBDiemH2pl/022cSB6MP/ieFW8pLm5GNkNgA/7m9doVWOlaZdQ7fVSUJNVjKvRGKzwaFZTfeJe" +
		"bKiQHXqT88q0zXVYxTrhAkEA6pQYhh2gj/ZQz8PbCKGcEBbRkCYbJhfHSZYnb428ZM0uSJjWXZ4Kme" +
		"B0k4hNG04hyCKm90ovKHWd4hSGEjKALQJBAMZn437gfbzi2eIUkpNY7DZU668Iq1KpIL1rLen8MZLp" +
		"TnN6AiJy4cwIHMyTzxBITpN0tONofy2sR5C8wDyiVcUCQFsv3qij87qCwb9CH28ng4ctl6E1bvBL5g" +
		"hQ+lt++XEl4YwO/aW+vdg7TJXdMjwfDzrBXa5bhCFyN0GfQM7qGrECQQDEK+49Afxw6Z/jMNIojJCp" +
		"u9d4rkqvJXiwsSupoejmSHaAKQ+5PfvR/+dxw2fFwqimlYtRGn49C42LJ4Wvrha9AkB9a/bIefI6IA" +
		"HzX17ofsT/CEAl94EsGgTO7liWgCmlvo/EOFcrIFuz5FKRwEkzsZnGzRYpXxLRbUOrlKij/Dfu"

	privateKeyBase64, err := base64.StdEncoding.DecodeString(testClientPrivateKey)
	require.NoError(t, err)
	privKey, err := x509.ParsePKCS1PrivateKey(privateKeyBase64)
	require.NoError(t, err)
	return privKey
}
