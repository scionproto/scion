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
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	prepareDP := func(ctrl *gomock.Controller) *DataPlane {
		ret := &DataPlane{Metrics: metrics}

		key := []byte("testkey_xxxxxxxx")
		local := xtest.MustParseIA("1-ff00:0:110")
		counter := 0
		mInternal := mock_router.NewMockBatchConn(ctrl)
		mInternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
			func(m underlayconn.Messages) (int, error) {
				for i := 0; i < 10; i++ {
					spkt, dpath := prepBaseMsg(time.Now())
					spkt.DstIA = local
					dpath.HopFields = []path.HopField{
						{ConsIngress: 41, ConsEgress: 40},
						{ConsIngress: 31, ConsEgress: 30},
						{ConsIngress: 1, ConsEgress: 0},
					}
					dpath.Base.PathMeta.CurrHF = 0
					dpath.HopFields[0].Mac = computeMAC(t, key,
						dpath.InfoFields[0], dpath.HopFields[2])
					spkt.Path = dpath
					payload := bytes.Repeat([]byte("actualpayloadbytes"), i)
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
					ret.running = false
				}
				return 10, nil
			},
		).Times(2)
		mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

		_ = ret.AddInternalInterface(mInternal, net.IP{})
		_ = ret.SetIA(local)
		_ = ret.SetKey(key)
		return ret
	}
	dp := prepareDP(ctrl)
	runConfig := &RunConfig{
		NumProcessorRoutines: 1,
		InterfaceBatchSize:   64,
		ProcessorQueueSize:   64,
		ForwarderQueueSize:   64,
		RandomValue:          []byte{1, 2, 3, 4},
	}
	dp.populateInterfaces()
	dp.initializePacketPool(runConfig)
	dp.initializeChannels(runConfig)
	initialPoolSize := len(dp.packetPool)
	dp.running = true
	dp.initMetrics()
	go func() {
		dp.runReceiver(0, dp.internal, runConfig)
	}()
	for i := 0; i < 21; i++ {
		select {
		case <-dp.procChannels[0]:
			// make sure that the pool size has decreased
			assert.Greater(t, initialPoolSize, len(dp.packetPool))
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
		totalCount := 255
		expectedPktId := byte(0)
		mInternal.EXPECT().WriteBatch(gomock.Any(), 0).DoAndReturn(
			func(ms underlayconn.Messages, flags int) (int, error) {
				if totalCount == 0 {
					return 0, nil
				}
				for i, m := range ms {
					totalCount--
					// 1/5 of the packets (randomly chosen) are errors
					if scrypto.RandInt64()%5 == 0 {
						expectedPktId++
						ms = ms[:i]
						break
					} else {
						pktId := m.Buffers[0][0]
						if expectedPktId != pktId {
							ret.running = false
							t.Log("packets got reordered.",
								"expected", expectedPktId, "got", pktId, "ms", ms)
							t.Fail()
							done <- struct{}{}
						}
						expectedPktId++
					}
				}
				if totalCount == 0 {
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
		NumProcessorRoutines: 20,
		InterfaceBatchSize:   64,
		ProcessorQueueSize:   64,
		ForwarderQueueSize:   64,
		RandomValue:          []byte{1, 2, 3, 4},
	}
	dp.populateInterfaces()
	dp.initializePacketPool(runConfig)
	dp.initializeChannels(runConfig)
	initialPoolSize := len(dp.packetPool)
	dp.running = true
	dp.initMetrics()
	go func() {
		dp.runForwarder(0, dp.internal, runConfig)
	}()
	for i := 0; i < 255; i++ {
		pkt := <-dp.packetPool
		assert.NotEqual(t, initialPoolSize, len(dp.packetPool))
		pkt[0] = byte(i)
		select {
		case dp.forwardChannels[0] <- packet{
			srcAddr:   nil,
			dstAddr:   nil,
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
	flowIdBuffer := [3]byte{}
	hasher := fnv.New32a()
	hashForScionPacket := func(flowBuf []byte, tmpBuffer []byte, s *slayers.SCION) uint32 {
		hasher := fnv.New32a()
		hasher.Write(randomValue)
		hasher.Write(flowBuf[1:4])
		s.SerializeAddrHdr(tmpBuffer)
		hasher.Write(tmpBuffer[:s.AddrHdrLen()])
		return hasher.Sum32() % uint32(numProcs)
	}

	// this internal function compares the hash value using the scion parsed packet
	// with the custom extraction in dataplane.omputeProcID()
	compareHash := func(payload []byte, s *slayers.SCION) uint32 {
		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer,
			gopacket.SerializeOptions{FixLengths: true},
			s, gopacket.Payload(payload))
		require.NoError(t, err)
		raw := buffer.Bytes()
		flowBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(flowBuf, s.FlowID)
		flowBuf[0] &= 0xF
		tmpBuffer := make([]byte, 100)
		val1 := hashForScionPacket(flowBuf, tmpBuffer, s)
		val2, err := computeProcId(raw, numProcs, randomValue, flowIdBuffer, hasher)
		assert.NoError(t, err)
		assert.Equal(t, val1, val2)
		return val1
	}

	key := []byte("testkey_xxxxxxxx")
	local := xtest.MustParseIA("1-ff00:0:110")
	spkt, dpath := prepBaseMsg(time.Now())
	spkt.DstIA = local
	spkt.FlowID = (1 << 20) - 1
	dpath.HopFields = []path.HopField{
		{ConsIngress: 41, ConsEgress: 40},
		{ConsIngress: 31, ConsEgress: 30},
		{ConsIngress: 1, ConsEgress: 0},
	}
	dpath.Base.PathMeta.CurrHF = 2
	dpath.HopFields[2].Mac = computeMAC(t, key,
		dpath.InfoFields[0], dpath.HopFields[2])
	spkt.Path = dpath
	payload := []byte("x")
	// now we test with the packet as defined above
	val1 := compareHash(payload, spkt)
	// now we change the payload to make sure that this does not
	// affect the hashing
	payload = make([]byte, 100)
	for i := 0; i < 10; i++ {
		_, err := rand.Read(payload)
		assert.NoError(t, err)
		newVal := compareHash(payload, spkt)
		assert.Equal(t, val1, newVal)
	}
	// now we modify the traffic class to make sure that even
	// though it share a byte with the flowId, it does not affect
	// the hashing
	spkt.TrafficClass = 0
	for i := 0; i < 16; i++ {
		compareHash(payload, spkt)
		spkt.TrafficClass++
	}
}

func prepBaseMsg(now time.Time) (*slayers.SCION, *scion.Decoded) {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
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
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []path.HopField{},
	}
	return spkt, dpath
}

func computeMAC(t *testing.T, key []byte, info path.InfoField, hf path.HopField) [path.MacLen]byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(t, err)
	return path.MAC(mac, info, hf, nil)
}
