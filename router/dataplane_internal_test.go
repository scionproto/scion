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

package router

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/gopacket/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	underlayconn "github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router/mock_router"
)

var (
	testKey = []byte("testkey_xxxxxxxx")
)

// TestReceiver sets up a mocked batchConn, starts the receiver that reads from
// this batchConn and forwards it to the processing routines channels. We verify
// by directly reading from the processing routine channels that we received
// the same number of packets as the receiver received.
func TestReceiver(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	dp := &DataPlane{Metrics: metrics}
	counter := 0
	mInternal := mock_router.NewMockBatchConn(ctrl)
	done := make(chan bool)
	mInternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
		func(m underlayconn.Messages) (int, error) {
			for i := 0; i < 10; i++ {
				payload := bytes.Repeat([]byte("actualpayloadbytes"), i)
				raw := serializedBaseMsg(t, payload, 0)
				copy(m[i].Buffers[0], raw)
				m[i].N = len(raw)
				m[i].Addr = &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}
				counter++
			}
			return 10, nil
		},
	).Times(2)
	mInternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
		func(m underlayconn.Messages) (int, error) {
			dp.setStopping()
			done <- true
			return 0, nil
		},
	).Times(1)

	_ = dp.AddInternalInterface(mInternal, netip.Addr{})

	runConfig := &RunConfig{
		NumProcessors: 1,
		BatchSize:     64,
	}
	dp.initPacketPool(runConfig, 64)
	procCh, _, _ := initQueues(runConfig, dp.interfaces, 64)
	initialPoolSize := len(dp.packetPool)
	dp.setRunning()
	dp.initMetrics()
	go func() {
		dp.runReceiver(0, dp.interfaces[0], runConfig, procCh)
	}()
	ptrMap := make(map[uintptr]struct{})
	for i := 0; i < 21; i++ {
		select {
		case pkt := <-procCh[0]:
			// make sure that the pool size has decreased
			assert.Greater(t, initialPoolSize, len(dp.packetPool))
			// make sure that the packet has the right size
			assert.Equal(t, 84+i%10*18, len(pkt.rawPacket))
			// make sure that the source address was set correctly
			assert.Equal(t, net.UDPAddr{IP: net.IP{10, 0, 200, 200}}, *pkt.srcAddr)
			// make sure that the received pkt buffer has not been seen before
			ptr := reflect.ValueOf(pkt.rawPacket).Pointer()
			assert.NotContains(t, ptrMap, ptr)
			ptrMap[ptr] = struct{}{}
		case <-time.After(50 * time.Millisecond):
			// make sure that the processing routine received exactly 20 messages
			if i != 20 {
				t.Fail()
				dp.setStopping()
			}
		}
	}
	<-done
	// make sure that the packet pool has the expected size after the test
	assert.Equal(t, initialPoolSize-runConfig.BatchSize-20, len(dp.packetPool))
}

// TestForwarder sets up a mocked batchConn, starts the forwarder that will write to
// this batchConn and forwards some packets to the channel of the forwarder. We then
// verify that the forwarder has sent all the packets, no packets got reordered
// and that the buffers have been returned to the buffer pool.
func TestForwarder(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	done := make(chan struct{})
	prepareDP := func(ctrl *gomock.Controller) *DataPlane {
		ret := &DataPlane{Metrics: metrics}

		mInternal := mock_router.NewMockBatchConn(ctrl)
		totalCount := 0
		expectedPktId := byte(0)
		mInternal.EXPECT().WriteBatch(gomock.Any(), 0).DoAndReturn(
			func(ms underlayconn.Messages, flags int) (int, error) {
				if totalCount == 255 {
					return 0, nil
				}
				for i, m := range ms {
					totalCount++
					// 1/5 of the packets (randomly chosen) are errors
					if mrand.IntN(5) == 0 {
						expectedPktId++
						ms = ms[:i]
						break
					} else {
						pktId := m.Buffers[0][0]
						if !assert.Equal(t, expectedPktId, pktId) {
							t.Log("packets got reordered.",
								"expected", expectedPktId, "got", pktId, "ms", ms)
						}
						if totalCount <= 100 {
							assert.NotNil(t, m.Addr)
						} else {
							// stronger check than assert.Nil
							assert.True(t, m.Addr == nil)
						}
						expectedPktId++
					}
				}
				if totalCount == 255 {
					ret.setStopping()
					done <- struct{}{}
				}
				if len(ms) == 0 {
					return 0, nil
				}

				return len(ms), nil
			}).AnyTimes()
		_ = ret.AddInternalInterface(mInternal, netip.Addr{})
		return ret
	}
	dp := prepareDP(ctrl)
	runConfig := &RunConfig{
		NumProcessors: 20,
		BatchSize:     64,
	}
	dp.initPacketPool(runConfig, 64)
	_, fwCh, _ := initQueues(runConfig, dp.interfaces, 64)
	initialPoolSize := len(dp.packetPool)
	dp.setRunning()
	dp.initMetrics()
	go dp.runForwarder(0, dp.interfaces[0], runConfig, fwCh[0])

	dstAddr := &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}
	for i := 0; i < 255; i++ {
		pkt := <-dp.packetPool
		pkt.reset()
		pkt.rawPacket = pkt.rawPacket[:1]
		pkt.rawPacket[0] = byte(i)
		if i < 100 {
			pkt.dstAddr.IP = pkt.dstAddr.IP[:4]
			copy(pkt.dstAddr.IP, dstAddr.IP)
		}
		pkt.srcAddr = &net.UDPAddr{} // Receiver always sets this.
		pkt.ingress = 0

		assert.NotEqual(t, initialPoolSize, len(dp.packetPool))

		select {
		case fwCh[0] <- pkt:
		case <-done:
		}

	}
	select {
	case <-done:
		time.Sleep(100 * time.Millisecond)
		assert.Equal(t, initialPoolSize, len(dp.packetPool))
	case <-time.After(100 * time.Millisecond):
		t.Fail()
		dp.setStopping()
	}
}

func TestComputeProcId(t *testing.T) {
	randomValueBytes := []byte{1, 2, 3, 4}
	numProcs := 10000

	// ComputeProcID expects the per-receiver random number to be pre-hashed into the seed that we
	// pass.
	hashSeed := fnv1aOffset32
	for _, c := range randomValueBytes {
		hashSeed = hashFNV1a(hashSeed, c)
	}

	// this function returns the procID as we expect it by using the  slayers.SCION serialization
	// implementation.
	referenceHash := func(s *slayers.SCION) uint32 {
		flowBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(flowBuf, s.FlowID)
		flowBuf[0] &= 0xF
		tmpBuffer := make([]byte, 100)
		hasher := fnv.New32a()
		hasher.Write(randomValueBytes)
		hasher.Write(flowBuf[1:4])
		if err := s.SerializeAddrHdr(tmpBuffer); err != nil {
			panic(err)
		}
		hasher.Write(tmpBuffer[:s.AddrHdrLen()])
		return hasher.Sum32() % uint32(numProcs)
	}

	// this helper returns the procID as the router actually makes it by using the extraction
	// from dataplane.computeProcID() along with hashFNV1a() for the seed.
	computeProcIDHelper := func(payload []byte, s *slayers.SCION) (uint32, error) {
		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer,
			gopacket.SerializeOptions{FixLengths: true},
			s, gopacket.Payload(payload))
		require.NoError(t, err)
		raw := buffer.Bytes()

		return computeProcID(raw, numProcs, hashSeed)
	}
	type ret struct {
		payload []byte
		s       *slayers.SCION
	}
	// Each testcase has a function that returns a set of ret structs where
	// all rets of that set are expected to return the same hash value
	testCases := map[string]func(t *testing.T) []ret{
		"basic": func(t *testing.T) []ret {
			payload := []byte("x")
			return []ret{
				{
					payload: payload,
					s:       prepBaseMsg(t, payload, (1<<20)-1),
				},
			}
		},
		"different payload does not affect hashing": func(t *testing.T) []ret {
			rets := make([]ret, 10)
			for i := 0; i < 10; i++ {
				rets[i].payload = make([]byte, 100)
				_, err := rand.Read(rets[i].payload)
				spkt := prepBaseMsg(t, rets[i].payload, 1)
				assert.NoError(t, err)
				rets[i].s = spkt
			}
			return rets
		},
		"flowID is extracted correctly independing of trafficId": func(t *testing.T) []ret {
			rets := make([]ret, 16)
			payload := make([]byte, 100)
			for i := 0; i < 16; i++ {
				rets[i].payload = payload
				spkt := prepBaseMsg(t, rets[i].payload, 1)
				spkt.TrafficClass = uint8(i)
				rets[i].s = spkt
			}
			return rets
		},
		"ipv4 to ipv4": func(t *testing.T) []ret {
			payload := make([]byte, 100)
			spkt := prepBaseMsg(t, payload, 1)
			_ = spkt.SetDstAddr(addr.HostIP(netip.AddrFrom4([4]byte{10, 0, 200, 200})))
			_ = spkt.SetSrcAddr(addr.HostIP(netip.AddrFrom4([4]byte{10, 0, 200, 200})))
			assert.Equal(t, slayers.T4Ip, spkt.DstAddrType)
			assert.Equal(t, slayers.T4Ip, spkt.SrcAddrType)
			return []ret{
				{
					payload: payload,
					s:       spkt,
				},
			}
		},
		"ipv6 to ipv4": func(t *testing.T) []ret {
			payload := make([]byte, 100)
			spkt := prepBaseMsg(t, payload, 1)
			_ = spkt.SetDstAddr(addr.HostIP(netip.AddrFrom4([4]byte{10, 0, 200, 200})))
			_ = spkt.SetSrcAddr(addr.HostIP(netip.MustParseAddr("2001:db8::68")))
			assert.Equal(t, slayers.T4Ip, spkt.DstAddrType)
			assert.Equal(t, slayers.T16Ip, int(spkt.SrcAddrType))
			return []ret{
				{
					payload: payload,
					s:       spkt,
				},
			}
		},
		"svc to ipv4": func(t *testing.T) []ret {
			payload := make([]byte, 100)
			spkt := prepBaseMsg(t, payload, 1)
			spkt.DstAddrType = slayers.T4Ip
			_ = spkt.SetDstAddr(addr.HostIP(netip.AddrFrom4([4]byte{10, 0, 200, 200})))
			_ = spkt.SetSrcAddr(addr.HostSVC(addr.SvcWildcard))
			assert.Equal(t, slayers.T4Ip, spkt.DstAddrType)
			assert.Equal(t, slayers.T4Svc, int(spkt.SrcAddrType))
			return []ret{
				{
					payload: payload,
					s:       spkt,
				},
			}
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			rets := tc(t)
			if len(rets) == 0 {
				return
			}
			expected := referenceHash(rets[0].s)
			for _, r := range rets {
				actual, err := computeProcIDHelper(r.payload, r.s)
				// this tests do not test errors, hence no errors should occur
				assert.NoError(t, err)
				assert.Equal(t, expected, actual)
			}
		})
	}
}

func TestComputeProcIdErrorCases(t *testing.T) {
	type test struct {
		data          []byte
		expectedError error
	}
	testCases := map[string]test{
		"packet shorter than common header len": {
			data:          make([]byte, 10),
			expectedError: serrors.New("Packet is too short"),
		},
		"packet len = CmnHdrLen + addrHdrLen": {
			data: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0,
			},
			expectedError: nil,
		},
		"packet len < CmnHdrLen + addrHdrLen": {
			data: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0,
			},
			expectedError: serrors.New("Packet is too short"),
		},
		"packet len = CmnHdrLen + addrHdrLen (16IP)": {
			data: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0x33, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0,
			},
			expectedError: nil,
		},
		"packet len < CmnHdrLen + addrHdrLen (16IP)": {
			data: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0x33, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0,
			},
			expectedError: serrors.New("Packet is too short"),
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			randomValue := uint32(1234) // not a proper hash seed, but hash result is irrelevant.
			_, actualErr := computeProcID(tc.data, 10000, randomValue)
			if tc.expectedError != nil {
				assert.Equal(t, tc.expectedError.Error(), actualErr.Error())
			} else {
				assert.NoError(t, actualErr)
			}
		})
	}
}

func TestSlowPathProcessing(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	payload := []byte("actualpayloadbytes")

	// ProcessPacket assumes some pre-conditions:
	// * The ingress interface has to exist. This fake map is good for the test cases we have.
	// * InternalNextHops may not be nil. Empty is ok for all the test cases we have.
	fakeExternalInterfaces := map[uint16]BatchConn{1: nil}
	fakeInternalNextHops := map[uint16]netip.AddrPort{}
	fakeServices := map[addr.SVC][]netip.AddrPort{}

	testCases := map[string]struct {
		mockMsg                 func() []byte
		prepareDP               func(*gomock.Controller) *DataPlane
		expectedSlowPathRequest slowPathRequest
		srcInterface            uint16
		expectedLayerType       gopacket.LayerType
	}{
		"svc nobackend": {
			prepareDP: func(ctrl *gomock.Controller) *DataPlane {
				return NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops,
					fakeServices,
					addr.MustParseIA("1-ff00:0:110"),
					nil, testKey)
			},
			mockMsg: func() []byte {
				spkt := prepBaseMsg(t, payload, 0)
				_ = spkt.SetDstAddr(addr.MustParseHost("CS"))
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				ret := toMsg(t, spkt)
				return ret
			},
			srcInterface: 1,
			expectedSlowPathRequest: slowPathRequest{
				typ:      slowPathSCMP,
				scmpType: slayers.SCMPTypeDestinationUnreachable,
				code:     slayers.SCMPCodeNoRoute,
			},
			expectedLayerType: slayers.LayerTypeSCMPDestinationUnreachable,
		},
		"svc invalid": {
			prepareDP: func(ctrl *gomock.Controller) *DataPlane {
				return NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops,
					fakeServices,
					addr.MustParseIA("1-ff00:0:110"), nil, testKey)
			},
			mockMsg: func() []byte {
				spkt := prepBaseMsg(t, payload, 0)
				_ = spkt.SetDstAddr(addr.MustParseHost("CS"))
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				ret := toMsg(t, spkt)
				return ret
			},
			srcInterface: 1,
			expectedSlowPathRequest: slowPathRequest{
				typ:      slowPathSCMP,
				scmpType: slayers.SCMPTypeDestinationUnreachable,
				code:     slayers.SCMPCodeNoRoute,
			},
			expectedLayerType: slayers.LayerTypeSCMPDestinationUnreachable,
		},
		"invalid dest": {
			prepareDP: func(ctrl *gomock.Controller) *DataPlane {
				return NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops,
					fakeServices,
					addr.MustParseIA("1-ff00:0:110"), nil, testKey)
			},
			mockMsg: func() []byte {
				spkt := prepBaseMsg(t, payload, 0)
				spkt.DstIA = addr.MustParseIA("1-ff00:0:f1")
				ret := toMsg(t, spkt)
				return ret
			},
			srcInterface: 1,
			expectedSlowPathRequest: slowPathRequest{
				typ:      slowPathSCMP,
				scmpType: slayers.SCMPTypeParameterProblem,
				code:     slayers.SCMPCodeInvalidDestinationAddress,
				pointer:  0xc,
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid dest addr": {
			prepareDP: func(ctrl *gomock.Controller) *DataPlane {
				return NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops,
					fakeServices,
					addr.MustParseIA("1-ff00:0:110"), nil, testKey)
			},
			mockMsg: func() []byte {
				spkt := prepBaseMsg(t, payload, 0)
				spkt.RawDstAddr = []byte("invalid")
				spkt.DstAddrType = 1 // invalid address type
				ret := toMsg(t, spkt)
				return ret
			},
			srcInterface: 1,
			expectedSlowPathRequest: slowPathRequest{
				typ:      slowPathSCMP,
				scmpType: slayers.SCMPTypeParameterProblem,
				code:     slayers.SCMPCodeInvalidDestinationAddress,
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid dest v4mapped": {
			prepareDP: func(ctrl *gomock.Controller) *DataPlane {
				return NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops,
					fakeServices,
					addr.MustParseIA("1-ff00:0:110"), nil, testKey)
			},
			mockMsg: func() []byte {
				spkt := prepBaseMsg(t, payload, 0)
				spkt.DstAddrType = slayers.T16Ip
				spkt.RawDstAddr = []byte{
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 200, 200,
				}
				ret := toMsg(t, spkt)
				return ret
			},
			srcInterface: 1,
			expectedSlowPathRequest: slowPathRequest{
				typ:      slowPathSCMP,
				scmpType: slayers.SCMPTypeParameterProblem,
				code:     slayers.SCMPCodeInvalidDestinationAddress,
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid dest unspecified": {
			prepareDP: func(ctrl *gomock.Controller) *DataPlane {
				return NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops,
					fakeServices,
					addr.MustParseIA("1-ff00:0:110"), nil, testKey)
			},
			mockMsg: func() []byte {
				spkt := prepBaseMsg(t, payload, 0)
				spkt.DstAddrType = slayers.T4Ip
				spkt.RawDstAddr = []byte{0, 0, 0, 0}
				ret := toMsg(t, spkt)
				return ret
			},
			srcInterface: 1,
			expectedSlowPathRequest: slowPathRequest{
				typ:      slowPathSCMP,
				scmpType: slayers.SCMPTypeParameterProblem,
				code:     slayers.SCMPCodeInvalidDestinationAddress,
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid src v4mapped": {
			prepareDP: func(ctrl *gomock.Controller) *DataPlane {
				return NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops,
					fakeServices,
					addr.MustParseIA("1-ff00:0:111"), nil, testKey)
			},
			mockMsg: func() []byte {
				spkt := prepBaseMsgHop0Out(t, payload, 0)
				_ = spkt.SetDstAddr(addr.HostIP(netip.AddrFrom4([4]byte{10, 0, 200, 200})))
				spkt.SrcAddrType = slayers.T16Ip
				spkt.RawSrcAddr = []byte{
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 200, 100,
				}
				ret := toMsg(t, spkt)
				return ret
			},
			srcInterface: 0,
			expectedSlowPathRequest: slowPathRequest{
				typ:      slowPathSCMP,
				scmpType: slayers.SCMPTypeParameterProblem,
				code:     slayers.SCMPCodeInvalidSourceAddress,
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dp := tc.prepareDP(ctrl)
			dp.initMetrics()

			rp := tc.mockMsg()
			pkt := packet{}
			pkt.init(&[bufSize]byte{})
			pkt.reset()
			pkt.ingress = tc.srcInterface
			pkt.srcAddr = &net.UDPAddr{} // The receiver always sets this.
			pkt.rawPacket = pkt.rawPacket[:len(rp)]
			copy(pkt.rawPacket, rp)

			processor := newPacketProcessor(dp)
			disp := processor.processPkt(&pkt)
			assert.Equal(t, pSlowPath, disp)

			assert.Equal(t, tc.expectedSlowPathRequest, pkt.slowPathRequest)
			slowPathProcessor := newSlowPathProcessor(dp)
			err := slowPathProcessor.processPacket(&pkt)
			assert.NoError(t, err)

			// here we parse the outgoing packet to verify that it contains the correct SCMP
			// header and typecodes.
			packet := gopacket.NewPacket(pkt.rawPacket, slayers.LayerTypeSCION, gopacket.Default)
			scmp := packet.Layer(slayers.LayerTypeSCMP).(*slayers.SCMP)
			expectedTypeCode := slayers.CreateSCMPTypeCode(tc.expectedSlowPathRequest.scmpType,
				tc.expectedSlowPathRequest.code)
			assert.Equal(t, expectedTypeCode, scmp.TypeCode)
			assert.NotNil(t, packet.Layer(tc.expectedLayerType))
		})
	}
}

func toMsg(t *testing.T, spkt *slayers.SCION) []byte {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	payload := []byte("actualpayloadbytes")
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		spkt, gopacket.Payload(payload))
	require.NoError(t, err)
	raw := buffer.Bytes()
	ret := make([]byte, bufSize)
	copy(ret, raw)
	return ret[:len(raw)]
}

func computeMAC(t *testing.T, key []byte, info path.InfoField, hf path.HopField) [path.MacLen]byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(t, err)
	return path.MAC(mac, info, hf, nil)
}

func serializedBaseMsg(t *testing.T, payload []byte, flowId uint32) []byte {
	s := prepBaseMsg(t, payload, flowId)
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer,
		gopacket.SerializeOptions{FixLengths: true},
		s, gopacket.Payload(payload))
	assert.NoError(t, err)
	return buffer.Bytes()
}

// Prepares a message that is arriving at its last hop, incoming through interface 1.
func prepBaseMsg(t *testing.T, payload []byte, flowId uint32) *slayers.SCION {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       flowId,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        addr.MustParseIA("1-ff00:0:110"),
		SrcIA:        addr.MustParseIA("1-ff00:0:111"),
		Path:         &scion.Raw{},
		PayloadLen:   18,
	}

	dpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 2,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(time.Now())},
		},

		HopFields: []path.HopField{
			{ConsIngress: 41, ConsEgress: 40},
			{ConsIngress: 31, ConsEgress: 30},
			{ConsIngress: 1, ConsEgress: 0},
		},
	}
	dpath.HopFields[2].Mac = computeMAC(t, testKey, dpath.InfoFields[0], dpath.HopFields[2])
	spkt.Path = dpath
	return spkt
}

// Prepares a message that is at its first hop and outgoing via interface 1.
func prepBaseMsgHop0Out(t *testing.T, payload []byte, flowId uint32) *slayers.SCION {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       flowId,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        addr.MustParseIA("1-ff00:0:110"),
		SrcIA:        addr.MustParseIA("1-ff00:0:111"),
		Path:         &scion.Raw{},
		PayloadLen:   18,
	}

	dpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 0,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(time.Now())},
		},

		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 1},
			{ConsIngress: 41, ConsEgress: 40},
			{ConsIngress: 31, ConsEgress: 30},
		},
	}
	dpath.HopFields[0].Mac = computeMAC(t, testKey, dpath.InfoFields[0], dpath.HopFields[0])
	spkt.Path = dpath
	return spkt
}
