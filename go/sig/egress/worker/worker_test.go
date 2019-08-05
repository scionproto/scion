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
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/sig/egress"
	"github.com/scionproto/scion/go/sig/egress/mock_egress"
	"github.com/scionproto/scion/go/sig/metrics"
	"github.com/scionproto/scion/go/sig/mgmt"
)

func TestMain(m *testing.M) {
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}

func SendPacket(t *testing.T, r *ringbuf.Ring, pkt []byte) {
	bufs := make(ringbuf.EntryList, 1)
	n, _ := egress.EgressFreePkts.Read(bufs, true)
	assert.Equal(t, 1, n)
	buf := bufs[0].(common.RawBytes)
	buf = buf[:len(pkt)]
	copy(buf, pkt)
	n, _ = r.Write(ringbuf.EntryList{buf}, true)
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

	ia, _ := addr.IAFromString("1-ff00:0:300")
	r := ringbuf.New(64, nil, "egress", prometheus.Labels{"ringId": "", "sessId": ""})

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	s := mock_egress.NewMockSession(mockCtrl)
	s.EXPECT().IA().AnyTimes().Return(ia)
	s.EXPECT().ID().AnyTimes().Return(mgmt.SessionType(0))
	s.EXPECT().Conn().AnyTimes().Return(nil)
	s.EXPECT().Ring().AnyTimes().Return(r)
	s.EXPECT().Remote().AnyTimes().Return(nil)
	s.EXPECT().Cleanup().AnyTimes().Return(nil)
	s.EXPECT().Healthy().AnyTimes().Return(true)
	s.EXPECT().PathPool().AnyTimes().Return(nil)

	writer := NewMockWriter()
	w := NewWorker(s, writer, true, logger)
	go func() {
		w.Run()
	}()

	// Simple packet.
	SendPacket(t, r, []byte{1, 2, 3})
	writer.AssertFrame(t, []byte{0, 0, 0, 0, 0, 0, 0, 1,
		0, 3, 1, 2, 3})

	// Two packets in a single frame.
	SendPacket(t, r, []byte{4, 5, 6})
	SendPacket(t, r, []byte{7, 8})
	writer.AssertFrame(t, []byte{0, 0, 0, 0, 0, 1, 0, 1,
		0, 3, 4, 5, 6, 0, 0, 0,
		0, 2, 7, 8})

	// Single packet split into two frames.
	SendPacket(t, r, make([]byte, 2000))
	writer.AssertFrame(t, append([]byte{0, 0, 0, 0, 0, 2, 0, 1,
		7, 208}, make([]byte, 1254)...))
	writer.AssertFrame(t, append([]byte{0, 0, 0, 0, 0, 3, 0, 0},
		make([]byte, 746)...))

	// Second packet starting at non-zero position in the second frame.
	SendPacket(t, r, make([]byte, 2000))
	SendPacket(t, r, []byte{10, 11, 12})
	writer.AssertFrame(t, append([]byte{0, 0, 0, 0, 0, 4, 0, 1,
		7, 208}, make([]byte, 1254)...))
	exp := []byte{0, 0, 0, 0, 0, 5, 0, 95}
	exp = append(exp, make([]byte, 746)...)
	exp = append(exp, []byte{0, 0, 0, 0, 0, 0}...) // padding at the end of 1st packet
	exp = append(exp, []byte{0, 3, 10, 11, 12}...)
	writer.AssertFrame(t, exp)

	r.Close()
}
