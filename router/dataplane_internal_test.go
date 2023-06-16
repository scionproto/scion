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
	"encoding/binary"
	"hash/fnv"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	underlayconn "github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router/mock_router"
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
	key := []byte("testkey_xxxxxxxx")
	local := xtest.MustParseIA("1-ff00:0:110")
	mInternal := mock_router.NewMockBatchConn(ctrl)

	mInternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
		func(m underlayconn.Messages) (int, error) {
			for i := 0; i < 10; i++ {
				payload := bytes.Repeat([]byte("actualpayloadbytes"), i)
				spkt := prepBaseMsg(t, payload, 0)

				buffer := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buffer,
					gopacket.SerializeOptions{FixLengths: true},
					spkt, gopacket.Payload(payload))
				require.NoError(t, err)
				raw := buffer.Bytes()
				copy(m[i].Buffers[0], raw)
				m[i].N = len(raw)
				m[i].Addr = &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}
				counter++
			}
			if counter == 20 {
				dp.running = false
			}
			return 10, nil
		},
	).Times(2)
	mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

	_ = dp.AddInternalInterface(mInternal, net.IP{})
	_ = dp.SetIA(local)
	_ = dp.SetKey(key)

	runConfig := &RunConfig{
		NumProcessors: 1,
		BatchSize:     64,
	}
	dp.initPacketPool(runConfig, 64)
	procCh, _ := initQueues(runConfig, dp.interfaces, 64)
	initialPoolSize := len(dp.packetPool)
	dp.running = true
	dp.initMetrics()
	go func() {
		dp.runReceiver(0, dp.internal, runConfig, procCh)
	}()
	for i := 0; i < 21; i++ {
		select {
		case pkt := <-procCh[0]:
			// make sure that the pool size has decreased
			assert.Greater(t, initialPoolSize, len(dp.packetPool))
			// make sure that the packet has the right size
			assert.Equal(t, 84+i%10*18, len(pkt.rawPacket))
			// make sure that the source address was set correctly
			assert.Equal(t, net.UDPAddr{IP: net.IP{10, 0, 200, 200}}, *pkt.srcAddr)
		case <-time.After(50 * time.Millisecond):
			// make sure that the processing routine received exactly 20 messages
			if i != 20 {
				t.Fail()
				dp.running = false
			}
		}
	}
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

		key := []byte("testkey_xxxxxxxx")
		local := xtest.MustParseIA("1-ff00:0:110")
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
					if rand.Intn(5) == 0 {
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
							if m.Addr == nil {
								t.Fail()
								t.Log("Address is nil", m.Addr)
							}
						} else {
							if m.Addr != nil {
								t.Fail()
								t.Log("Address is not nil", m.Addr)
							}
						}

						expectedPktId++
					}
				}
				if totalCount == 255 {
					ret.running = false
					done <- struct{}{}
				}
				if len(ms) == 0 {
					return 0, nil
				}

				return len(ms), nil
			}).AnyTimes()
		_ = ret.AddInternalInterface(mInternal, net.IP{})
		_ = ret.SetIA(local)
		_ = ret.SetKey(key)
		return ret
	}
	dp := prepareDP(ctrl)
	runConfig := &RunConfig{
		NumProcessors: 20,
		BatchSize:     64,
	}
	dp.initPacketPool(runConfig, 64)
	_, fwCh := initQueues(runConfig, dp.interfaces, 64)
	initialPoolSize := len(dp.packetPool)
	dp.running = true
	dp.initMetrics()
	go dp.runForwarder(0, dp.internal, runConfig, fwCh[0])

	dstAddr := &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}
	for i := 0; i < 255; i++ {
		pkt := <-dp.packetPool
		assert.NotEqual(t, initialPoolSize, len(dp.packetPool))
		pkt[0] = byte(i)
		if i == 100 {
			dstAddr = nil
		}
		select {
		case fwCh[0] <- packet{
			srcAddr:   nil,
			dstAddr:   dstAddr,
			ingress:   0,
			rawPacket: pkt[:1],
		}:
		case <-done:
		}

	}
	select {
	case <-done:
		time.Sleep(100 * time.Millisecond)
		assert.Equal(t, initialPoolSize, len(dp.packetPool))
	case <-time.After(100 * time.Millisecond):
		t.Fail()
		dp.running = false
	}
}

func TestComputeProcId(t *testing.T) {
	randomValue := []byte{1, 2, 3, 4}
	numProcs := 10000
	hashForScionPacket := func(s *slayers.SCION) uint32 {
		flowBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(flowBuf, s.FlowID)
		flowBuf[0] &= 0xF
		tmpBuffer := make([]byte, 100)
		hasher := fnv.New32a()
		hasher.Write(randomValue)
		hasher.Write(flowBuf[1:4])
		if err := s.SerializeAddrHdr(tmpBuffer); err != nil {
			return 0
		}
		hasher.Write(tmpBuffer[:s.AddrHdrLen()])
		return hasher.Sum32() % uint32(numProcs)
	}

	// this internal function compares the hash value using the scion parsed packet
	// with the custom extraction in dataplane.computeProcID()
	compareHash := func(payload []byte, s *slayers.SCION) uint32 {
		flowIdBuffer := make([]byte, 3)
		hasher := fnv.New32a()
		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer,
			gopacket.SerializeOptions{FixLengths: true},
			s, gopacket.Payload(payload))
		require.NoError(t, err)
		raw := buffer.Bytes()

		val1 := hashForScionPacket(s)
		val2, err := computeProcID(raw, numProcs, randomValue, flowIdBuffer, hasher)
		assert.NoError(t, err)
		assert.Equal(t, val1, val2)
		return val1
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
			_ = spkt.SetDstAddr(&net.IPAddr{IP: net.IP{10, 0, 200, 200}})
			_ = spkt.SetSrcAddr(&net.IPAddr{IP: net.IP{10, 0, 200, 200}})
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
			_ = spkt.SetDstAddr(&net.IPAddr{IP: net.IP{10, 0, 200, 200}})
			_ = spkt.SetSrcAddr(&net.IPAddr{IP: net.ParseIP("2001:db8::68")})
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
			_ = spkt.SetDstAddr(&net.IPAddr{IP: net.IP{10, 0, 200, 200}})
			_ = spkt.SetSrcAddr(addr.HostSVCFromString("BS_A"))
			assert.Equal(t, slayers.T4Ip, spkt.DstAddrType)
			assert.Equal(t, slayers.T4Svc, int(spkt.SrcAddrType))
			return []ret{
				{
					payload: payload,
					s:       spkt,
				},
			}
		},
		"undefined to ipv4": func(t *testing.T) []ret {
			payload := make([]byte, 100)
			spkt := prepBaseMsg(t, payload, 1)
			spkt.DstAddrType = slayers.T4Ip
			_ = spkt.SetDstAddr(&net.IPAddr{IP: net.IP{10, 0, 200, 200}})
			// UDPAddr is currently considered undefined when parsing
			_ = spkt.SetSrcAddr(&net.UDPAddr{IP: net.IP{10, 0, 200, 200}})
			assert.Equal(t, slayers.T4Ip, spkt.DstAddrType)
			assert.Equal(t, 0, int(spkt.SrcAddrType))
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
			valueToCompare := uint32(0)
			for i, r := range tc(t) {
				v := compareHash(r.payload, r.s)
				if i == 0 {
					valueToCompare = v
				} else {
					// make sure that all packets yield the same hash
					assert.Equal(t, valueToCompare, v)
				}
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
			randomValue := []byte{1, 2, 3, 4}
			flowIdBuffer := make([]byte, 3)
			_, actualErr := computeProcID(tc.data, 10000, randomValue, flowIdBuffer, fnv.New32a())
			if tc.expectedError != nil {
				assert.Equal(t, tc.expectedError.Error(), actualErr.Error())
			} else {
				assert.NoError(t, actualErr)
			}
		})
	}
}

func prepBaseMsg(t *testing.T, payload []byte, flowId uint32) *slayers.SCION {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       flowId,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        xtest.MustParseIA("1-ff00:0:110"),
		SrcIA:        xtest.MustParseIA("1-ff00:0:111"),
		Path:         &scion.Raw{},
		PayloadLen:   18,
	}

	dpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
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
	dpath.Base.PathMeta.CurrHF = 2
	dpath.HopFields[2].Mac = computeMAC(t, []byte("testkey_xxxxxxxx"),
		dpath.InfoFields[0], dpath.HopFields[2])
	spkt.Path = dpath
	return spkt
}

func computeMAC(t *testing.T, key []byte, info path.InfoField, hf path.HopField) [path.MacLen]byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(t, err)
	return path.MAC(mac, info, hf, nil)
}
