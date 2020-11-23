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
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/mocks/net/mock_net"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestNoPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	frameChan := make(chan ([]byte))
	sess := createSession(t, ctrl, frameChan)
	sendPackets(t, sess, 22, 10)
	// No path was set. Make sure that no frames are generated.
	waitFrames(t, frameChan, 0, 0)
	sess.Close()
}

func TestSinglePath(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	frameChan := make(chan ([]byte))
	sess := createSession(t, ctrl, frameChan)
	sess.SetPath(createMockPath(ctrl, 200))
	sendPackets(t, sess, 22, 10)
	waitFrames(t, frameChan, 22, 10)
	sess.Close()
}

func TestTwoPaths(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Unbuffered channel guarantees that the frames won't be sent out
	// immediately, but only when waitFrames is called.
	frameChan := make(chan ([]byte))

	sess := createSession(t, ctrl, frameChan)

	sess.SetPath(createMockPath(ctrl, 200))
	sendPackets(t, sess, 22, 10)

	// The previous packets are not yet sent, yet we set a new path thus creating a new
	// sender. The goal is to test that the old packets will still be sent out.
	sess.SetPath(createMockPath(ctrl, 200))
	sendPackets(t, sess, 22, 10)
	waitFrames(t, frameChan, 22, 20)

	sess.Close()
}

func createSession(t *testing.T, ctrl *gomock.Controller, frameChan chan []byte) *Session {
	conn := mock_net.NewMockPacketConn(ctrl)
	conn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IP{192, 168, 1, 1}}).AnyTimes()
	conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(
		func(f []byte, _ interface{}) (int, error) {
			frameChan <- f
			return 0, nil
		}).AnyTimes()
	return &Session{
		SessionID:     22,
		DataPlaneConn: conn,
	}
}

func sendPackets(t *testing.T, sess *Session, payloadSize int, pktCount int) {
	pkt := append([]byte{
		// IPv4 header.
		0x40, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}, make([]byte, payloadSize)...)
	for i := 0; i < pktCount; i++ {
		sess.Write(pkt)
	}
}

func waitFrames(t *testing.T, frameChan chan []byte, payloadSize int, pktCount int) {
	// Wait for outgoing frames. Make sure that the total length of the outgoing
	// data matches the total length of the packets.
	toRead := (20 + payloadSize) * pktCount
	for toRead > 0 {
		frame := <-frameChan
		payloadLen := len(frame) - hdrLen
		toRead -= payloadLen
	}
	// Make sure that we haven't got more data than expected.
	assert.Equal(t, 0, toRead)
	// Wait some more to make sure that no more frames are coming.
	timer := time.NewTimer(50 * time.Millisecond)
	select {
	case <-frameChan:
		assert.Fail(t, "Unexpected frame received")
	case <-timer.C:
	}
}

func createMockPath(ctrl *gomock.Controller, mtu uint16) snet.Path {
	meta := &snet.PathMetadata{
		MTU: mtu,
	}
	path := mock_snet.NewMockPath(ctrl)
	path.EXPECT().Destination().Return(xtest.MustParseIA("1-ff00:0:300")).AnyTimes()
	path.EXPECT().Metadata().Return(meta).AnyTimes()
	path.EXPECT().Path().Return(spath.Path{Raw: []byte{}}).AnyTimes()
	path.EXPECT().UnderlayNextHop().Return(nil).AnyTimes()
	path.EXPECT().Copy().Return(path).AnyTimes()
	return path
}
