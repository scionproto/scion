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

package main

import (
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/underlay/conn"
	"github.com/scionproto/scion/go/lib/underlay/conn/mock_conn"
)

func TestIsSyscallErrno(t *testing.T) {
	tests := map[string]struct {
		Error     error
		Errno     syscall.Errno
		Assertion assert.BoolAssertionFunc
	}{
		"ECONNREFUSED": {
			Error:     &net.OpError{Err: &os.SyscallError{Err: syscall.ECONNREFUSED}},
			Errno:     syscall.ECONNREFUSED,
			Assertion: assert.True,
		},
		"ENETUNREACH": {
			Error:     &net.OpError{Err: &os.SyscallError{Err: syscall.ENETUNREACH}},
			Errno:     syscall.ENETUNREACH,
			Assertion: assert.True,
		},
		"EHOSTUNREACH": {
			Error:     &net.OpError{Err: &os.SyscallError{Err: syscall.EHOSTUNREACH}},
			Errno:     syscall.EHOSTUNREACH,
			Assertion: assert.True,
		},
		"EPERM": {
			Error:     &net.OpError{Err: &os.SyscallError{Err: syscall.EPERM}},
			Errno:     syscall.EPERM,
			Assertion: assert.True,
		},
		"Wrapped(EPERM)": {
			Error:     serrors.WrapStr("wrapped", syscall.EPERM),
			Errno:     syscall.EPERM,
			Assertion: assert.True,
		},
		"mismatch": {
			Error:     &net.OpError{Err: &os.SyscallError{Err: syscall.EHOSTUNREACH}},
			Errno:     syscall.EPERM,
			Assertion: assert.False,
		},
		"other": {
			Error:     serrors.New("other"),
			Errno:     syscall.EPERM,
			Assertion: assert.False,
		},
	}
	for n, tc := range tests {
		name, test := n, tc
		t.Run(name, func(t *testing.T) {
			test.Assertion(t, isSyscallErrno(test.Error, test.Errno))
		})
	}
}

func TestPosixOutputNoLeakNoErrors(t *testing.T) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	r := initTestRouter(1)
	pkts, checkAllReturned := newTestPktList(t, 2*outputBatchCnt)
	defer checkAllReturned(len(pkts))
	// Wait for both batches to be written.
	done := make(chan struct{}, 1)
	mconn := newTestConn(mctrl)
	mconn.EXPECT().WriteBatch(gomock.Any()).Times(2).DoAndReturn(testSuccessfulWrite(done))
	sock := newTestSock(r, len(pkts), mconn)
	sock.Start()
	sock.Ring.Write(pkts, true)
	<-done
	<-done
	sock.Stop()
}

func TestPosixOutputNoLeakTemporaryErrors(t *testing.T) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	r := initTestRouter(1)
	pkts, checkAllReturned := newTestPktList(t, 2*outputBatchCnt)
	defer checkAllReturned(len(pkts))
	// Wait for both batches to be written.
	done := make(chan struct{}, 1)
	mconn := newTestConn(mctrl)
	mconn.EXPECT().WriteBatch(gomock.Any()).Return(0, tempTestErr{})
	mconn.EXPECT().WriteBatch(gomock.Any()).Times(2).DoAndReturn(testSuccessfulWrite(done))
	sock := newTestSock(r, len(pkts), mconn)
	sock.Start()
	sock.Ring.Write(pkts, true)
	<-done
	<-done
	sock.Stop()
}

func TestPosixOutputNoLeakRecoverableErrors(t *testing.T) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	r := initTestRouter(1)
	pkts, checkAllReturned := newTestPktList(t, 2*outputBatchCnt)
	defer checkAllReturned(len(pkts))
	// Wait for both batches to be written.
	done := make(chan struct{}, 1)
	mconn := newTestConn(mctrl)
	err := &net.OpError{Err: &os.SyscallError{Err: syscall.ECONNREFUSED}}
	mconn.EXPECT().WriteBatch(gomock.Any()).Return(0, err)
	mconn.EXPECT().WriteBatch(gomock.Any()).DoAndReturn(testSuccessfulWrite(done))
	sock := newTestSock(r, len(pkts), mconn)
	sock.Start()
	sock.Ring.Write(pkts, true)
	<-done
	sock.Stop()
}

func testSuccessfulWrite(done chan<- struct{}) func(conn.Messages) (int, error) {
	return func(msgs conn.Messages) (int, error) {
		for i, msg := range msgs {
			msgs[i].N = len(msg.Buffers[0])
		}
		done <- struct{}{}
		return outputBatchCnt, nil
	}
}

func newTestConn(mctrl *gomock.Controller) *mock_conn.MockConn {
	mconn := mock_conn.NewMockConn(mctrl)
	mconn.EXPECT().LocalAddr().AnyTimes().Return(nil)
	mconn.EXPECT().RemoteAddr().AnyTimes().Return(nil)
	mconn.EXPECT().SetReadDeadline(gomock.Any())
	mconn.EXPECT().Close()
	return mconn
}

func newTestPktList(t *testing.T, length int) (ringbuf.EntryList, func(expected int)) {
	var freeCtr int
	entries := make(ringbuf.EntryList, length)
	for i := range entries {
		rp := rpkt.NewRtrPkt()
		rp.Logger = log.Root()
		rp.Free = func(rp *rpkt.RtrPkt) {
			freeCtr++
		}
		entries[i] = &rpkt.EgressRtrPkt{Rp: rp, Dst: newTestDst(t)}
	}
	return entries, func(expected int) {
		require.Equal(t, expected, freeCtr, "Invalid number of freed packets")
	}
}

func newTestDst(t *testing.T) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: topology.EndhostPort,
	}
}

func newTestSock(r *Router, ringSize int, mconn conn.Conn) *rctx.Sock {
	return rctx.NewSock(ringbuf.New(ringSize, nil, "loc_out"), mconn, 0, 12, prom.LabelNeighIA,
		nil, r.posixOutput, PosixSock)
}

type tempTestErr struct{}

func (tempTestErr) Error() string { return "temporary" }

func (tempTestErr) Temporary() bool { return true }
