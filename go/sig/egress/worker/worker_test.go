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

package worker

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/sig/egress"
	"github.com/scionproto/scion/go/sig/metrics"
	"github.com/scionproto/scion/go/sig/mgmt"
)

func NewMockSession(logger log.Logger) *MockSession {
	return &MockSession{
		Logger: logger.New(),
		ring: ringbuf.New(64, nil, "egress",
			prometheus.Labels{"ringId": "", "sessId": ""}),
	}
}

type MockSession struct {
	log.Logger
	ring *ringbuf.Ring
}

func (self *MockSession) IA() addr.IA {
	ia, _ := addr.IAFromString("1-ff00:0:300")
	return ia
}

func (self *MockSession) ID() mgmt.SessionType {
	return 0
}

func (self *MockSession) Conn() snet.Conn {
	return nil
}

func (self *MockSession) Ring() *ringbuf.Ring {
	return self.ring
}

func (self *MockSession) Remote() *egress.RemoteInfo {
	return nil
}

func (self *MockSession) Cleanup() error {
	return nil
}

func (self *MockSession) Healthy() bool {
	return true
}

func (self *MockSession) PathPool() egress.PathPool {
	return nil
}

func (self *MockSession) AnnounceWorkerStopped() {
}

func (self *MockSession) SendPacket(t *testing.T, pkt []byte) {
	bufs := make(ringbuf.EntryList, 1)
	n, _ := egress.EgressFreePkts.Read(bufs, true)
	assert.Equal(t, 1, n)
	buf := bufs[0].(common.RawBytes)
	buf = buf[:len(pkt)]
	copy(buf, pkt)
	n, _ = self.ring.Write(ringbuf.EntryList{buf}, true)
	assert.Equal(t, 1, n)
}

func NewMockWriter() *MockWriter {
	return &MockWriter{ch: make(chan []byte)}
}

type MockWriter struct {
	ch chan []byte
}

func (self *MockWriter) WriteToSCION(b []byte, address *snet.Addr) (int, error) {
	f := make([]byte, len(b))
	copy(f, b)
	self.ch <- f
	return len(f), nil
}

func (self *MockWriter) AssertFrame(t *testing.T, expected []byte) {
	f := <-self.ch
	// Epoch numbers (f[1:3]) are random. Ignore them.
	assert.Equal(t, expected[0], f[0])
	assert.Equal(t, expected[3:], f[3:])
}

func TestParsing(t *testing.T) {
	metrics.Init("")
	egress.Init()
	logger := log.New()
	session := NewMockSession(logger)
	writer := NewMockWriter()
	w := NewWorker(session, writer, true, logger)
	go func() {
		w.Run()
	}()

	// Simple packet.
	session.SendPacket(t, []byte{1, 2, 3})
	writer.AssertFrame(t, []byte{0, 0, 0, 0, 0, 0, 0, 1,
		0, 3, 1, 2, 3})

	// Two packets in a single frame.
	session.SendPacket(t, []byte{4, 5, 6})
	session.SendPacket(t, []byte{7, 8})
	writer.AssertFrame(t, []byte{0, 0, 0, 0, 0, 1, 0, 1,
		0, 3, 4, 5, 6, 0, 0, 0,
		0, 2, 7, 8})

	// Single packet split into two frames.
	session.SendPacket(t, make([]byte, 2000))
	writer.AssertFrame(t, append([]byte{0, 0, 0, 0, 0, 2, 0, 1,
		7, 208}, make([]byte, 1254)...))
	writer.AssertFrame(t, append([]byte{0, 0, 0, 0, 0, 3, 0, 0},
		make([]byte, 746)...))

	// Second packet starting at non-zero position in the second frame.
	session.SendPacket(t, make([]byte, 2000))
	session.SendPacket(t, []byte{10, 11, 12})
	writer.AssertFrame(t, append([]byte{0, 0, 0, 0, 0, 4, 0, 1,
		7, 208}, make([]byte, 1254)...))
	exp := []byte{0, 0, 0, 0, 0, 5, 0, 95}
	exp = append(exp, make([]byte, 746)...)
	exp = append(exp, []byte{0, 0, 0, 0, 0, 0}...) // padding at the end of 1st packet
	exp = append(exp, []byte{0, 3, 10, 11, 12}...)
	writer.AssertFrame(t, exp)

	session.ring.Close()
}
