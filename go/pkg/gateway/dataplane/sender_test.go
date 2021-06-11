// Copyright 2020 Anapaya Systems
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

package dataplane

import (
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/scionproto/scion/go/lib/mocks/net/mock_net"
)

func expectFrames(conn *mock_net.MockPacketConn) *gomock.Call {
	return conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(
		func(f []byte, _ interface{}) (int, error) {
			// Slow down the sending to induce packet batching.
			time.Sleep(10 * time.Millisecond)
			return 0, nil
		})
}

func waitForFrames() {
	time.Sleep(100 * time.Millisecond)
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestSender(t *testing.T) {
	type WriteCall struct {
		Payload []byte
		Wait    bool
	}

	createPkt := func(payload []byte) []byte {
		ip := &layers.IPv4{
			Version: 4,
			SrcIP:   net.IP{10, 0, 0, 2},
			DstIP:   net.IP{10, 0, 0, 1},
		}
		buf := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
			ip, gopacket.Payload(payload))
		require.NoError(t, err)
		return buf.Bytes()
	}

	tests := map[string]struct {
		Writes       []WriteCall
		ExpFrames    int
		ExpMaxFrames int
	}{
		"single packet": {
			Writes: []WriteCall{
				{Payload: createPkt([]byte{1, 2, 3}), Wait: true},
			},
			ExpFrames: 1,
		},
		"two packets": {
			Writes: []WriteCall{
				{Payload: createPkt([]byte{1, 2, 3}), Wait: true},
				{Payload: createPkt([]byte{4, 5}), Wait: true},
			},
			ExpFrames: 2,
		},
		"batching": {
			Writes: []WriteCall{
				{Payload: createPkt([]byte{1, 2, 3})},
				{Payload: createPkt([]byte{1, 2, 3})},
				{Payload: createPkt([]byte{1, 2, 3}), Wait: true},
			},
			ExpMaxFrames: 2,
		},
		"Splitting": {
			Writes: []WriteCall{
				{Payload: createPkt(make([]byte, 300)), Wait: true},
			},
			ExpFrames: 2,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			conn := mock_net.NewMockPacketConn(ctrl)
			conn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IP{192, 168, 1, 1}}).AnyTimes()
			addr := net.UDPAddr{
				IP:   net.IP{192, 168, 1, 2},
				Port: 30041,
			}
			c, err := newSender(1, conn, createMockPath(ctrl, 256), addr, nil, SessionMetrics{})
			require.NoError(t, err)
			defer c.Close()
			if test.ExpFrames != 0 {
				expectFrames(conn).Times(test.ExpFrames)
			} else {
				expectFrames(conn).MaxTimes(test.ExpMaxFrames)
			}
			// Run all writes
			for _, write := range test.Writes {
				c.Write(write.Payload)
				if write.Wait {
					waitForFrames()
				}
			}
		})
	}
}
