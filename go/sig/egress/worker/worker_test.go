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
	"fmt"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/sig_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/sig/egress/iface"
	"github.com/scionproto/scion/go/sig/egress/iface/mock_iface"
	"github.com/scionproto/scion/go/sig/egress/worker/mock_worker"
)

func TestMain(m *testing.M) {
	log.Discard()
	os.Exit(m.Run())
}

type FrameMatcher struct {
	pattern []byte
}

func MatchFrame(pattern []byte) gomock.Matcher {
	return &FrameMatcher{pattern}
}

func (fm *FrameMatcher) Matches(x interface{}) bool {
	frame := x.([]byte)
	// Match all the bytes except the epoch.
	if len(frame) != len(fm.pattern) {
		return false
	}
	if frame[0] != fm.pattern[0] {
		return false
	}
	for i, v := range frame[3:] {
		if v != fm.pattern[i+3] {
			return false
		}
	}
	return true
}

func (fm *FrameMatcher) String() string {
	return fmt.Sprintf("matches %v", fm.pattern)
}

type WorkerTester struct {
	t        *testing.T
	mockCtrl *gomock.Controller
	writer   *mock_worker.MockSCIONWriter
	ring     *ringbuf.Ring
}

func NewWorkerTester(t *testing.T) *WorkerTester {
	tester := &WorkerTester{t: t}
	tester.mockCtrl = gomock.NewController(t)
	tester.writer = mock_worker.NewMockSCIONWriter(tester.mockCtrl)
	tester.ring = ringbuf.New(64, nil, "egress")
	return tester
}

func (wt *WorkerTester) ExpectFrame(frame []byte) {
	wt.writer.EXPECT().WriteTo(MatchFrame(frame), gomock.Any()).Return(len(frame), nil)
}

func (wt *WorkerTester) ExpectLastFrame(frame []byte) {
	wt.writer.EXPECT().WriteTo(MatchFrame(frame), gomock.Any()).DoAndReturn(
		func(frame []byte, address *snet.UDPAddr) (int, error) {
			wt.ring.Close()
			return len(frame), nil
		})
}

func (wt *WorkerTester) SendPacket(pkt []byte) {
	bufs := make(ringbuf.EntryList, 1)
	n, _ := iface.EgressFreePkts.Read(bufs, true)
	assert.Equal(wt.t, 1, n)
	buf := bufs[0].(common.RawBytes)
	buf = buf[:len(pkt)]
	copy(buf, pkt)
	n, _ = wt.ring.Write(ringbuf.EntryList{buf}, true)
	assert.Equal(wt.t, 1, n)
}

func (wt *WorkerTester) Run() {
	ia, _ := addr.IAFromString("1-ff00:0:300")
	s := mock_iface.NewMockSession(wt.mockCtrl)
	s.EXPECT().IA().AnyTimes().Return(ia)
	s.EXPECT().ID().AnyTimes().Return(sig_mgmt.SessionType(0))
	s.EXPECT().Conn().AnyTimes().Return(nil)
	s.EXPECT().Ring().AnyTimes().Return(wt.ring)
	s.EXPECT().Remote().AnyTimes().Return(nil)
	s.EXPECT().Cleanup().AnyTimes().Return(nil)
	s.EXPECT().Healthy().AnyTimes().Return(true)
	s.EXPECT().PathPool().AnyTimes().Return(nil)
	s.EXPECT().AnnounceWorkerStopped().AnyTimes()
	NewWorker(s, wt.writer, true, log.New()).Run()
}

func (wt *WorkerTester) Finish() {
	wt.mockCtrl.Finish()
}

func TestParsing(t *testing.T) {
	iface.Init()

	t.Run("simple packet", func(t *testing.T) {
		tester := NewWorkerTester(t)
		defer tester.Finish()
		tester.SendPacket([]byte{1, 2, 3})
		tester.ExpectLastFrame([]byte{0, 0, 0, 0, 0, 0, 0, 1,
			0, 3, 1, 2, 3})
		tester.Run()
	})

	t.Run("two packets in a single frame", func(t *testing.T) {
		tester := NewWorkerTester(t)
		defer tester.Finish()
		tester.SendPacket([]byte{4, 5, 6})
		tester.SendPacket([]byte{7, 8})
		tester.ExpectLastFrame([]byte{0, 0, 0, 0, 0, 0, 0, 1,
			0, 3, 4, 5, 6, 0, 0, 0,
			0, 2, 7, 8})
		tester.Run()
	})

	t.Run("single packet split into two frames", func(t *testing.T) {
		tester := NewWorkerTester(t)
		defer tester.Finish()
		tester.SendPacket(make([]byte, 2000))
		tester.ExpectFrame(append([]byte{0, 0, 0, 0, 0, 0, 0, 1,
			7, 208}, make([]byte, 1250)...))
		tester.ExpectLastFrame(append([]byte{0, 0, 0, 0, 0, 1, 0, 0},
			make([]byte, 750)...))
		tester.Run()
	})

	t.Run("second packet starting at non-zero position in the second frame", func(t *testing.T) {
		tester := NewWorkerTester(t)
		defer tester.Finish()
		tester.SendPacket(make([]byte, 2000))
		tester.SendPacket([]byte{10, 11, 12})
		tester.ExpectFrame(append([]byte{0, 0, 0, 0, 0, 0, 0, 1,
			7, 208}, make([]byte, 1250)...))
		exp := []byte{0, 0, 0, 0, 0, 1, 0, 95}
		exp = append(exp, make([]byte, 746)...)
		exp = append(exp, []byte{0, 0, 0, 0, 0, 0}...) // padding at the end of 1st packet
		exp = append(exp, []byte{0, 3, 10, 11, 12}...)
		tester.ExpectLastFrame(exp)
		tester.Run()
	})
}
