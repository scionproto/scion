// Copyright 2019 Anapaya Systems
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

package ingress

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/xtest"
)

type MockTun struct {
	packets [][]byte
}

func (mt *MockTun) Read(p []byte) (n int, err error) {
	return n, nil
}

func (mt *MockTun) Write(p []byte) (n int, err error) {
	mt.packets = append(mt.packets, p)
	return n, nil
}

func (mt *MockTun) Close() error {
	return nil
}

func (mt *MockTun) AssertPacket(t *testing.T, expected []byte) {
	assert.NotEqual(t, 0, len(mt.packets))
	assert.Equal(t, expected, mt.packets[0])
	mt.packets = mt.packets[1:]
}

func (mt *MockTun) AssertDone(t *testing.T) {
	assert.Equal(t, 0, len(mt.packets))
}

func SendFrame(t *testing.T, w *Worker, data []byte) {
	frames := make(ringbuf.EntryList, 1)
	n := NewFrameBufs(frames)
	assert.Equal(t, 1, n)
	f := frames[0].(*FrameBuf)
	copy(f.raw, data)
	f.frameLen = len(data)
	w.processFrame(f)
}

func TestParsing(t *testing.T) {
	addr := &snet.UDPAddr{
		IA: xtest.MustParseIA("1-ff00:0:300"),
		Host: &net.UDPAddr{
			IP:   net.IP{192, 168, 1, 1},
			Port: 80,
		},
	}
	mt := &MockTun{}
	w := NewWorker(addr, 1, mt)

	// Single frame with a single 3-bytes long packet inside.
	SendFrame(t, w, []byte{1, 0, 1, 0, 0, 1, 0, 1,
		0, 3, 101, 102, 103, 0, 0, 0})
	mt.AssertPacket(t, []byte{101, 102, 103})
	mt.AssertDone(t)

	// Single frame with two packets inside.
	SendFrame(t, w, []byte{1, 0, 1, 0, 0, 2, 0, 1,
		0, 3, 101, 102, 103, 0, 0, 0,
		0, 3, 201, 202, 203, 0, 0, 0})
	mt.AssertPacket(t, []byte{101, 102, 103})
	mt.AssertPacket(t, []byte{201, 202, 203})
	mt.AssertDone(t)

	// Single packet split into two frames.
	SendFrame(t, w, []byte{1, 0, 1, 0, 0, 3, 0, 1,
		0, 8, 51, 52, 53, 54, 55, 56})
	SendFrame(t, w, []byte{1, 0, 1, 0, 0, 4, 0, 0,
		57, 58, 0, 0, 0, 0, 0, 0})
	mt.AssertPacket(t, []byte{51, 52, 53, 54, 55, 56, 57, 58})
	mt.AssertDone(t)

	// Packet at a non-zero position in the frame.
	SendFrame(t, w, []byte{1, 0, 1, 0, 0, 5, 0, 1,
		0, 8, 51, 52, 53, 54, 55, 56})
	SendFrame(t, w, []byte{1, 0, 1, 0, 0, 6, 0, 2,
		57, 58, 0, 0, 0, 0, 0, 0,
		0, 3, 61, 62, 63, 0, 0, 0})
	mt.AssertPacket(t, []byte{51, 52, 53, 54, 55, 56, 57, 58})
	mt.AssertPacket(t, []byte{61, 62, 63})
	mt.AssertDone(t)

	// A hole in the packet sequence.
	SendFrame(t, w, []byte{1, 0, 1, 0, 0, 7, 0, 1,
		0, 3, 101, 102, 103, 0, 0, 0})
	SendFrame(t, w, []byte{1, 0, 1, 0, 0, 9, 0, 1,
		0, 3, 201, 202, 203, 0, 0, 0})
	mt.AssertPacket(t, []byte{101, 102, 103})
	mt.AssertPacket(t, []byte{201, 202, 203})
	mt.AssertDone(t)

	// A frame with the trailing part of the packet is dropped.
	// The packet should be discarded.
	// The trailing bytes at the beginning of the subsequent frame
	// should be ignored.
	SendFrame(t, w, []byte{1, 0, 1, 0, 0, 10, 0, 1,
		0, 8, 51, 52, 53, 54, 55, 56})
	SendFrame(t, w, []byte{1, 0, 1, 0, 0, 12, 0, 2,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 201, 202, 203, 0, 0, 0})
	mt.AssertPacket(t, []byte{201, 202, 203})
	mt.AssertDone(t)
}
