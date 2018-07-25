// Copyright 2018 ETH Zurich
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

package reliable_test

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/mock_reliable"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	IA      = xtest.MustParseIA("1-ff00:0:101")
	AppAddr = &reliable.AppAddr{
		Addr: addr.HostFromIP(net.ParseIP("192.168.0.1")),
		Port: 60001,
	}
	RemoteAppAddr = &reliable.AppAddr{
		Addr: addr.HostFromIP(net.ParseIP("192.168.0.2")),
		Port: 60002,
	}
	// Mimic errors returned by package net
	sysErrorEPIPE      = &net.OpError{Err: os.NewSyscallError("foo", syscall.EPIPE)}
	sysErrorECONNRESET = &net.OpError{Err: os.NewSyscallError("foo", syscall.ECONNRESET)}
	ErrorTimeout       = common.NewBasicError("Timed out", nil)
)

func TestReconnectingRegister(t *testing.T) {
	testCases := []struct {
		Name                 string
		ClientAttempts       int
		MaxTimeoutPerAttempt time.Duration
		MinRetryInterval     time.Duration
		MockDispatcherSetup  func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher
		ShouldError          bool
	}{
		{
			Name:           "One attempt, disabled max timeout per attempt",
			ClientAttempts: 1,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						Register(IA, AppAddr, nil, addr.SvcNone).
						DoAndReturn(
							func(_, _, _, _ interface{}) (reliable.DispatcherConn, uint16, error) {
								return nil, AppAddr.Port, nil
							}),
				)
				return dispatcher
			},
			ShouldError: false,
		},
		{
			Name:                 "Five attempts, client retries due to MaxTimeoutPerInterval",
			ClientAttempts:       5,
			MaxTimeoutPerAttempt: 10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						DoAndReturn(
							func(_, _, _, _, timeout interface{}) (reliable.DispatcherConn,
								uint16, error) {
								time.Sleep(timeout.(time.Duration))
								return nil, uint16(0), ErrorTimeout
							}).
						Times(5),
				)
				return dispatcher
			},
			ShouldError: true,
		},
		{
			Name:                 "Five attempts, MinRetryInterval is set",
			ClientAttempts:       5,
			MaxTimeoutPerAttempt: 10 * time.Millisecond,
			MinRetryInterval:     50 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), ErrorTimeout).
						Times(5),
				)
				return dispatcher
			},
			ShouldError: true,
		},
		{
			Name:           "Five attempts, success on first",
			ClientAttempts: 5,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						Register(IA, AppAddr, nil, addr.SvcNone).Return(nil, AppAddr.Port, nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
	}
	Convey("Main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				dispatcher := tc.MockDispatcherSetup(ctrl)
				reconnectingDispatcher := reliable.NewReconnectingDispatcher(dispatcher,
					tc.ClientAttempts, tc.MaxTimeoutPerAttempt, tc.MinRetryInterval)
				_, _, err := reconnectingDispatcher.Register(IA, AppAddr, nil, addr.SvcNone)
				xtest.SoMsgError("err", err, tc.ShouldError)
			})
		}
	})
}

func TestReconnectingRegisterTimeout(t *testing.T) {
	testCases := []struct {
		Name                 string
		ClientAttempts       int
		MaxTimeoutPerAttempt time.Duration
		MinRetryInterval     time.Duration
		RegisterTimeout      time.Duration
		MockDispatcherSetup  func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher
		ShouldError          bool
	}{
		{
			Name:                 "One attempt, dispatcher responds OK",
			ClientAttempts:       1,
			MaxTimeoutPerAttempt: time.Second,
			RegisterTimeout:      10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, AppAddr.Port, nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
		{
			Name:                 "One attempt, dispatcher fails immediately",
			ClientAttempts:       1,
			MaxTimeoutPerAttempt: time.Second,
			RegisterTimeout:      10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE),
				)
				return dispatcher
			},
			ShouldError: true,
		},
		{
			Name:                 "One attempt, dispatcher fails with timeout",
			ClientAttempts:       1,
			MaxTimeoutPerAttempt: time.Second,
			RegisterTimeout:      10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						DoAndReturn(
							func(_, _, _, _, timeout interface{}) (reliable.DispatcherConn,
								uint16, error) {
								time.Sleep(timeout.(time.Duration))
								return nil, uint16(0), ErrorTimeout
							}),
				)
				return dispatcher
			},
			ShouldError: true,
		},
		{
			Name:                 "Five attempts, long timeout, client retries due to MaxTimeout",
			ClientAttempts:       5,
			MaxTimeoutPerAttempt: 50 * time.Millisecond,
			RegisterTimeout:      500 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						// Client will only have time to get through these
						// exchanges if MaxTimeoutPerAttempt is enforced.
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						DoAndReturn(
							func(_, _, _, _, timeout interface{}) (reliable.DispatcherConn,
								uint16, error) {
								time.Sleep(timeout.(time.Duration))
								return nil, uint16(0), ErrorTimeout
							}).Times(4),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						DoAndReturn(
							func(_, _, _, _, timeout interface{}) (reliable.DispatcherConn,
								uint16, error) {
								time.Sleep(timeout.(time.Duration))
								return nil, uint16(1234), nil
							}),
				)
				return dispatcher
			},
			ShouldError: false,
		},
		{
			Name:                 "Three attempts, dispatcher succeeds on third one",
			ClientAttempts:       3,
			MaxTimeoutPerAttempt: time.Second,
			RegisterTimeout:      10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(1234), nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
		{
			Name:                 "Three attempts, dispatcher succeeds on second one",
			ClientAttempts:       3,
			MaxTimeoutPerAttempt: time.Second,
			RegisterTimeout:      10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, AppAddr.Port, nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
		{
			Name:                 "Three attempts, dispatcher never succeeds",
			ClientAttempts:       3,
			MaxTimeoutPerAttempt: time.Second,
			RegisterTimeout:      10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE).
						Times(3),
				)
				return dispatcher
			},
			ShouldError: true,
		},
		{
			Name:                 "Many attempts, give up after 3 due to timeout",
			ClientAttempts:       10,
			MaxTimeoutPerAttempt: time.Second,
			RegisterTimeout:      50 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						DoAndReturn(
							func(_, _, _, _, timeout interface{}) (reliable.DispatcherConn,
								uint16, error) {
								time.Sleep(20 * time.Millisecond)
								return nil, uint16(0), sysErrorEPIPE
							}).MinTimes(1).MaxTimes(3), // never reach 10 attempts due to timeout
				)
				return dispatcher
			},
			ShouldError: true,
		},
		{
			Name:                 "Ten attempts, but not all go through due to minRetryInterval",
			ClientAttempts:       10,
			MaxTimeoutPerAttempt: time.Second,
			MinRetryInterval:     10 * time.Millisecond,
			RegisterTimeout:      50 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE).
						MaxTimes(6),
				)
				return dispatcher
			},
			ShouldError: true,
		},
	}

	Convey("Main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				dispatcher := tc.MockDispatcherSetup(ctrl)
				reconnectingDispatcher := reliable.NewReconnectingDispatcher(dispatcher,
					tc.ClientAttempts, tc.MaxTimeoutPerAttempt, tc.MinRetryInterval)

				_, _, err := reconnectingDispatcher.RegisterTimeout(IA, AppAddr, nil,
					addr.SvcNone, tc.RegisterTimeout)
				xtest.SoMsgError("err", err, tc.ShouldError)
			})
		}
	})
}

func TestReconnectingRegisterEarlyExit(t *testing.T) {
	testCases := []struct {
		Name                 string
		ClientAttempts       int
		MaxTimeoutPerAttempt time.Duration
		MinRetryInterval     time.Duration
		RegisterTimeout      time.Duration
		MockDispatcherSetup  func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher
		ShouldError          bool
	}{
		{
			Name:                 "Two attempts, but return early due to minRetryInterval",
			ClientAttempts:       2,
			MaxTimeoutPerAttempt: 50 * time.Millisecond,
			MinRetryInterval:     500 * time.Millisecond,
			RegisterTimeout:      300 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE),
				)
				return dispatcher
			},
			ShouldError: true,
		},
	}

	Convey("Main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				dispatcher := tc.MockDispatcherSetup(ctrl)
				reconnectingDispatcher := reliable.NewReconnectingDispatcher(dispatcher,
					tc.ClientAttempts, tc.MaxTimeoutPerAttempt, tc.MinRetryInterval)

				startTime := time.Now()
				// Register returns immediately with error, and due to the
				// large MinRetryInterval, we cannot fit in another call so we
				// return immediately.
				_, _, err := reconnectingDispatcher.RegisterTimeout(IA, AppAddr, nil,
					addr.SvcNone, tc.RegisterTimeout)
				endTime := time.Now()
				SoMsg("timing", endTime, ShouldHappenBefore, startTime.Add(50*time.Millisecond))

				xtest.SoMsgError("err", err, tc.ShouldError)
			})
		}
	})
}

func TestReconnectPortDoesNotChange(t *testing.T) {
	AppAddrPortZero := &reliable.AppAddr{Addr: AppAddr.Addr, Port: 0}

	testCases := []struct {
		Name                string
		ClientAttempts      int
		ClientTimeout       time.Duration
		MockDispatcherSetup func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher
		ShouldError         bool
	}{
		{
			Name:           "Register without port, then trigger reconnect and check port",
			ClientAttempts: 1,
			ClientTimeout:  10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				conn := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					conn.EXPECT().SetWriteDeadline(gomock.Any()),
					conn.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr).Return(0, sysErrorEPIPE),
					conn.EXPECT().SetReadDeadline(gomock.Any()),
					conn.EXPECT().SetWriteDeadline(gomock.Any()),
					conn.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				// Expect same port on second register
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddrPortZero, nil, addr.SvcNone, gomock.Any()).
						Return(conn, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(conn, AppAddr.Port, nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
	}
	Convey("Main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				dispatcher := tc.MockDispatcherSetup(ctrl)
				reconnectingDispatcher := reliable.NewReconnectingDispatcher(dispatcher,
					tc.ClientAttempts, 200*time.Millisecond, -1)
				conn, port, err := reconnectingDispatcher.RegisterTimeout(IA, AppAddrPortZero, nil,
					addr.SvcNone, 20*time.Millisecond)
				SoMsg("reg err", err, ShouldBeNil)
				SoMsg("port", port, ShouldEqual, AppAddr.Port)
				if tc.ClientTimeout == 0 {
					err = conn.SetWriteDeadline(time.Time{})
				} else {
					err = conn.SetWriteDeadline(time.Now().Add(tc.ClientTimeout))
				}
				SoMsg("deadline err", err, ShouldBeNil)
				_, err = conn.WriteTo([]byte{1, 2, 3, 4}, RemoteAppAddr)
				xtest.SoMsgError("err", err, tc.ShouldError)
			})
		}
	})
}

func TestReconnectWriteTo(t *testing.T) {
	testCases := []struct {
		Name                string
		ClientAttempts      int
		ClientTimeout       time.Duration
		MockDispatcherSetup func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher
		ShouldError         bool
	}{
		{
			Name:           "Connect, and do one successful write",
			ClientAttempts: 1,
			ClientTimeout:  10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				conn := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					conn.EXPECT().SetWriteDeadline(gomock.Any()),
					conn.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(conn, AppAddr.Port, nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
		{
			Name:           "Connect, and do one unsuccessful write with no reconnect",
			ClientAttempts: 1,
			ClientTimeout:  10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				conn := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					conn.EXPECT().SetWriteDeadline(gomock.Any()),
					conn.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr).Return(0, sysErrorEPIPE),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(conn, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE),
				)
				return dispatcher
			},
			ShouldError: true,
		},
		{
			Name:           "Connect, and do one unsuccessful write with 3 attempts to reconnect",
			ClientAttempts: 3,
			ClientTimeout:  10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				connA := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connA.EXPECT().SetWriteDeadline(gomock.Any()),
					connA.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr).Return(0, sysErrorEPIPE),
				)
				connB := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connB.EXPECT().SetReadDeadline(gomock.Any()),
					connB.EXPECT().SetWriteDeadline(gomock.Any()),
					connB.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(connA, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(connB, AppAddr.Port, nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
		{
			Name:           "Mixed failing writes and connects",
			ClientAttempts: 5,
			ClientTimeout:  20 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				connA := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connA.EXPECT().SetWriteDeadline(gomock.Any()),
					connA.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr).Return(0, sysErrorEPIPE),
				)
				connB := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connB.EXPECT().SetReadDeadline(gomock.Any()),
					connB.EXPECT().SetWriteDeadline(gomock.Any()),
					connB.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr).Return(0, sysErrorEPIPE),
				)
				connC := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connC.EXPECT().SetReadDeadline(gomock.Any()),
					connC.EXPECT().SetWriteDeadline(gomock.Any()),
					connC.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(connA, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE).MaxTimes(4),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(connB, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE).MaxTimes(4),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(connC, AppAddr.Port, nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
		{
			Name:           "Write fails, timeout during reconnect derived from write deadline",
			ClientAttempts: 10,
			ClientTimeout:  50 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				conn := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					conn.EXPECT().SetWriteDeadline(gomock.Any()),
					conn.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr).Return(0, sysErrorEPIPE),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, gomock.Any(), nil, addr.SvcNone, gomock.Any()).
						Return(conn, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, gomock.Any(), nil, addr.SvcNone, gomock.Any()).
						DoAndReturn(
							func(_, _, _, _,
								timeout interface{}) (reliable.DispatcherConn, uint16, error) {

								time.Sleep(20 * time.Millisecond)
								return nil, uint16(0), ErrorTimeout
							}).MinTimes(1).MaxTimes(3),
				)
				return dispatcher
			},
			ShouldError: true,
		},
		{
			// Even though there is no write deadline in the unit under test,
			// the underlying library might still timeout depending on its
			// implementation. The unit under test should not care about this
			// behavior, and attempt the predefined number of tries.
			Name:           "Write fails, timeout during reconnect with no write deadline",
			ClientAttempts: 3,
			ClientTimeout:  0,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				conn := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					conn.EXPECT().SetWriteDeadline(gomock.Any()),
					conn.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr).Return(0, sysErrorEPIPE),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, gomock.Any(), nil, addr.SvcNone, gomock.Any()).
						Return(conn, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, gomock.Any(), nil, addr.SvcNone, gomock.Any()).
						DoAndReturn(
							func(_, _, _, _,
								timeout interface{}) (reliable.DispatcherConn, uint16, error) {

								time.Sleep(20 * time.Millisecond)
								return nil, uint16(0), ErrorTimeout
							}).Times(3),
				)
				return dispatcher
			},
			ShouldError: true,
		},
	}

	Convey("Main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				dispatcher := tc.MockDispatcherSetup(ctrl)
				reconnectingDispatcher := reliable.NewReconnectingDispatcher(dispatcher,
					tc.ClientAttempts, 200*time.Millisecond, -1)
				conn, _, err := reconnectingDispatcher.RegisterTimeout(IA, AppAddr, nil,
					addr.SvcNone, 20*time.Millisecond)
				SoMsg("reg err", err, ShouldBeNil)
				if tc.ClientTimeout == 0 {
					err = conn.SetWriteDeadline(time.Time{})
				} else {
					err = conn.SetWriteDeadline(time.Now().Add(tc.ClientTimeout))
				}
				SoMsg("deadline err", err, ShouldBeNil)
				_, err = conn.WriteTo([]byte{1, 2, 3, 4}, RemoteAppAddr)
				xtest.SoMsgError("err", err, tc.ShouldError)
			})
		}
	})
}

func TestReconnectReadFrom(t *testing.T) {
	testCases := []struct {
		Name                string
		ClientAttempts      int
		ClientTimeout       time.Duration
		MockDispatcherSetup func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher
		ShouldError         bool
	}{
		{
			Name:           "Connect, and do one successful read",
			ClientAttempts: 1,
			ClientTimeout:  10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				conn := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					conn.EXPECT().SetReadDeadline(gomock.Any()),
					conn.EXPECT().ReadFrom(gomock.Any()),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(conn, AppAddr.Port, nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
		{
			Name:           "Connect, and do one unsuccessful read with no reconnect",
			ClientAttempts: 1,
			ClientTimeout:  10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				conn := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					conn.EXPECT().SetReadDeadline(gomock.Any()),
					conn.EXPECT().ReadFrom(gomock.Any()).Return(0, nil, sysErrorEPIPE),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(conn, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE),
				)
				return dispatcher
			},
			ShouldError: true,
		},
		{
			Name:           "Connect, and do one unsuccessful read with 3 attempts to reconnect",
			ClientAttempts: 3,
			ClientTimeout:  10 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				connA := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connA.EXPECT().SetReadDeadline(gomock.Any()),
					connA.EXPECT().ReadFrom(gomock.Any()).Return(0, nil, sysErrorEPIPE),
				)
				connB := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connB.EXPECT().SetReadDeadline(gomock.Any()),
					connB.EXPECT().SetWriteDeadline(gomock.Any()),
					connB.EXPECT().ReadFrom(gomock.Any()),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(connA, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(connB, AppAddr.Port, nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
		{
			Name:           "Mixed failing reads and connects",
			ClientAttempts: 5,
			ClientTimeout:  20 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				connA := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connA.EXPECT().SetReadDeadline(gomock.Any()),
					connA.EXPECT().ReadFrom(gomock.Any()).Return(0, nil, sysErrorEPIPE),
				)
				connB := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connB.EXPECT().SetReadDeadline(gomock.Any()),
					connB.EXPECT().SetWriteDeadline(gomock.Any()),
					connB.EXPECT().ReadFrom(gomock.Any()).Return(0, nil, sysErrorEPIPE),
				)
				connC := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connC.EXPECT().SetReadDeadline(gomock.Any()),
					connC.EXPECT().SetWriteDeadline(gomock.Any()),
					connC.EXPECT().ReadFrom(gomock.Any()),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(connA, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE).MaxTimes(4),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(connB, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(nil, uint16(0), sysErrorEPIPE).MaxTimes(4),
					dispatcher.EXPECT().
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(connC, AppAddr.Port, nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
		{
			Name:           "Read fails, timeout during reconnect derived from read deadline",
			ClientAttempts: 10,
			ClientTimeout:  50 * time.Millisecond,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				conn := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					conn.EXPECT().SetReadDeadline(gomock.Any()),
					conn.EXPECT().ReadFrom(gomock.Any()).Return(0, nil, sysErrorEPIPE),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, gomock.Any(), nil, addr.SvcNone, gomock.Any()).
						Return(conn, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, gomock.Any(), nil, addr.SvcNone, gomock.Any()).
						DoAndReturn(
							func(_, _, _, _,
								timeout interface{}) (reliable.DispatcherConn, uint16, error) {

								time.Sleep(20 * time.Millisecond)
								return nil, uint16(0), ErrorTimeout
							}).MinTimes(1).MaxTimes(3),
				)
				return dispatcher
			},
			ShouldError: true,
		},
		{
			// Even though there is no read deadline in the unit under test,
			// the underlying library might still timeout depending on its
			// implementation. The unit under test should not care about this
			// behavior, and attempt the predefined number of tries.
			Name:           "Read fails, timeout during reconnect with no read deadline",
			ClientAttempts: 3,
			ClientTimeout:  0,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				conn := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					conn.EXPECT().SetReadDeadline(gomock.Any()),
					conn.EXPECT().ReadFrom(gomock.Any()).Return(0, nil, sysErrorEPIPE),
				)
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				gomock.InOrder(
					dispatcher.EXPECT().
						RegisterTimeout(IA, gomock.Any(), nil, addr.SvcNone, gomock.Any()).
						Return(conn, AppAddr.Port, nil),
					dispatcher.EXPECT().
						RegisterTimeout(IA, gomock.Any(), nil, addr.SvcNone, gomock.Any()).
						DoAndReturn(
							func(_, _, _, _,
								timeout interface{}) (reliable.DispatcherConn, uint16, error) {

								time.Sleep(20 * time.Millisecond)
								return nil, uint16(0), ErrorTimeout
							}).Times(3),
				)
				return dispatcher
			},
			ShouldError: true,
		},
	}

	Convey("Main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				dispatcher := tc.MockDispatcherSetup(ctrl)
				reconnectingDispatcher := reliable.NewReconnectingDispatcher(dispatcher,
					tc.ClientAttempts, 200*time.Millisecond, -1)
				conn, _, err := reconnectingDispatcher.RegisterTimeout(IA, AppAddr, nil,
					addr.SvcNone, 20*time.Millisecond)
				SoMsg("reg err", err, ShouldBeNil)
				if tc.ClientTimeout == 0 {
					err = conn.SetReadDeadline(time.Time{})
				} else {
					err = conn.SetReadDeadline(time.Now().Add(tc.ClientTimeout))
				}
				SoMsg("deadline err", err, ShouldBeNil)
				_, _, err = conn.ReadFrom([]byte{1, 2, 3, 4})
				xtest.SoMsgError("err", err, tc.ShouldError)
			})
		}
	})
}

func TestReconnectingDeadline(t *testing.T) {
	testCases := []struct {
		Name                 string
		ClientAttempts       int
		MaxTimeoutPerAttempt time.Duration
		MinRetryInterval     time.Duration
		EnableDeadline       bool
		MockDispatcherSetup  func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher
		ShouldError          bool
	}{
		{
			Name:           "Normal register, check that deadlines are inherited on reconnect",
			ClientAttempts: 10,
			EnableDeadline: true,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				// Initial connection
				connA := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connA.EXPECT().SetDeadline(gomock.Any()),
					connA.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr).Return(0, sysErrorEPIPE),
				)
				// New connection, expect deadline inheritance calls after creation
				connB := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connB.EXPECT().SetReadDeadline(gomock.Any()),
					connB.EXPECT().SetWriteDeadline(gomock.Any()),
					connB.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr).Return(0, sysErrorEPIPE),
				)
				gomock.InOrder(
					dispatcher.EXPECT().
						Register(IA, AppAddr, nil, addr.SvcNone).
						DoAndReturn(
							func(_, _, _, _ interface{}) (reliable.DispatcherConn, uint16, error) {
								return connA, AppAddr.Port, nil
							}),
					dispatcher.EXPECT().
						// Due to the read/write deadline, new calls have timeouts
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						Return(connB, AppAddr.Port, nil),
					dispatcher.EXPECT().
						// Deadline was inherited by the new connection, so we
						// don't have time for all attempts.
						RegisterTimeout(IA, AppAddr, nil, addr.SvcNone, gomock.Any()).
						DoAndReturn(
							func(_, _, _, _, _ interface{}) (reliable.DispatcherConn,
								uint16, error) {
								time.Sleep(50 * time.Millisecond)
								return nil, uint16(0), sysErrorEPIPE
							}).
						MinTimes(2).MaxTimes(5),
				)
				return dispatcher
			},
			ShouldError: true,
		},
		{
			Name:           "Normal register, check that zero deadlines do not impose timeout",
			ClientAttempts: 10,
			MockDispatcherSetup: func(ctrl *gomock.Controller) *mock_reliable.MockDispatcher {
				dispatcher := mock_reliable.NewMockDispatcher(ctrl)
				// Initial connection
				connA := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connA.EXPECT().SetDeadline(gomock.Any()),
					connA.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr).Return(0, sysErrorEPIPE),
				)
				// New connection, expect deadline inheritance calls after creation
				connB := mock_reliable.NewMockDispatcherConn(ctrl)
				gomock.InOrder(
					connB.EXPECT().SetReadDeadline(gomock.Any()),
					connB.EXPECT().SetWriteDeadline(gomock.Any()),
					connB.EXPECT().WriteTo(gomock.Any(), RemoteAppAddr),
				)
				gomock.InOrder(
					dispatcher.EXPECT().
						Register(IA, AppAddr, nil, addr.SvcNone).
						DoAndReturn(
							func(_, _, _, _ interface{}) (reliable.DispatcherConn, uint16, error) {
								return connA, AppAddr.Port, nil
							}),
					dispatcher.EXPECT().
						// Due to the read/write deadline, new calls have timeouts
						Register(IA, AppAddr, nil, addr.SvcNone).
						Return(connB, AppAddr.Port, nil),
				)
				return dispatcher
			},
			ShouldError: false,
		},
	}
	Convey("Main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				dispatcher := tc.MockDispatcherSetup(ctrl)
				reconnectingDispatcher := reliable.NewReconnectingDispatcher(dispatcher,
					tc.ClientAttempts, tc.MaxTimeoutPerAttempt, tc.MinRetryInterval)
				conn, _, err := reconnectingDispatcher.Register(IA, AppAddr, nil, addr.SvcNone)
				SoMsg("register err", err, ShouldBeNil)
				if tc.EnableDeadline {
					err = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
					SoMsg("deadline err", err, ShouldBeNil)
				} else {
					err = conn.SetDeadline(time.Time{})
					SoMsg("deadline err", err, ShouldBeNil)
				}
				_, err = conn.WriteTo([]byte{1, 2, 3, 4}, RemoteAppAddr)
				xtest.SoMsgError("write err", err, tc.ShouldError)
			})
		}
	})
}
