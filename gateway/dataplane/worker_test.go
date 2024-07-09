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

package dataplane

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/ringbuf"
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
	if len(mt.packets) != 0 {
		assert.Equal(t, expected, mt.packets[0])
		mt.packets = mt.packets[1:]
	}
}

func (mt *MockTun) AssertDone(t *testing.T) {
	assert.Equal(t, 0, len(mt.packets))
}

func SendFrame(t *testing.T, w *worker, data []byte) {
	frames := make(ringbuf.EntryList, 1)
	n := newFrameBufs(frames)
	assert.Equal(t, 1, n)
	f := frames[0].(*frameBuf)
	copy(f.raw, data)
	f.frameLen = len(data)
	w.processFrame(context.Background(), f)
}

func TestParsing(t *testing.T) {
	addr := &snet.UDPAddr{
		IA: addr.MustParseIA("1-ff00:0:300"),
		Host: &net.UDPAddr{
			IP:   net.IP{192, 168, 1, 1},
			Port: 80,
		},
	}
	mt := &MockTun{}
	w := newWorker(addr, 1, mt, IngressMetrics{})

	// Single frame with a single IPv4 packet inside.
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		101, 102, 103,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		101, 102, 103,
	})
	mt.AssertDone(t)

	// Single frame with a single IPv6 packet inside.
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2,
		// IPv6 header.
		0x60, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		101, 102, 103,
	})
	mt.AssertPacket(t, []byte{
		// IPv6 header.
		0x60, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		101, 102, 103,
	})
	mt.AssertDone(t)

	// Single frame with two packets inside.
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3,
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		101, 102, 103,
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		201, 202, 203,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		101, 102, 103,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		201, 202, 203,
	})
	mt.AssertDone(t)

	// Single packet split into two frames.
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4,
		// IPv4 header.
		0x40, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		51, 52, 53, 54, 55, 56,
	})
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5,
		// Payload.
		57, 58,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		51, 52, 53, 54, 55, 56, 57, 58,
	})
	mt.AssertDone(t)

	// Packet at a non-zero position in the frame.
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 6,
		// IPv4 header.
		0x40, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload (unfinished).
		51, 52, 53, 54, 55, 56,
	})
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7,
		// Payload (continued).
		57, 58,
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		61, 62, 63,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		51, 52, 53, 54, 55, 56, 57, 58,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		61, 62, 63,
	})
	mt.AssertDone(t)

	// A hole in the packet sequence.
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 8,
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		101, 102, 103,
	})
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 10,
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		201, 202, 203,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		101, 102, 103,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		201, 202, 203,
	})
	mt.AssertDone(t)

	// A frame with the trailing part of the packet is dropped.
	// The half-read packet should be discarded.
	// The trailing bytes at the beginning of the subsequent frame
	// should be ignored.
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 11,
		// IPv4 header.
		0x40, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload (unfinished).
		51, 52, 53, 54, 55, 56,
	})
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 13,
		// Payload (a trailing part, but not the continuation of the previous payload).
		70, 71, 72, 73, 74, 75, 76, 77,
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		201, 202, 203,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		201, 202, 203,
	})
	mt.AssertDone(t)

	// Invalid packet. The remaining part of the frame should be dropped, but
	// the processing should catch up in the next frame.
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 14,
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload (unfinished).
		81, 82, 83,
		// IPv5 header - error!
		0x50, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 18, 19, 20,
	})
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 15,
		// Invalid packet (continued).
		21, 22, 23, 24, 25, 26, 27, 28,
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		91, 92, 93,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		81, 82, 83,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		91, 92, 93,
	})
	mt.AssertDone(t)

	// One packet split into 3 frames.
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4,
		// IPv4 header.
		0x40, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		51, 52, 53, 54, 55, 56,
	})
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5,
		// Payload.
		57, 58,
	})
	SendFrame(t, w, []byte{
		// SIG frame header.
		0, 1, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 6,
		// Payload.
		59, 60,
	})
	mt.AssertPacket(t, []byte{
		// IPv4 header.
		0x40, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Payload.
		51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
	})
	mt.AssertDone(t)
}
