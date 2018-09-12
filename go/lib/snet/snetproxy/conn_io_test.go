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

package snetproxy_test

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/snet/snetproxy"
	"github.com/scionproto/scion/go/lib/snet/snetproxy/mock_snetproxy"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestProxyConnIO(t *testing.T) {
	Convey("Given an underlying connection, a reconnecter and an IO operation", t, func() {
		ctrl := gomock.NewController(&xtest.PanickingReporter{T: t})
		defer ctrl.Finish()
		mockConn := NewMockConnWithAddrs(ctrl, localAddr, nil, bindAddr, addr.SvcNone)
		mockReconnecter := mock_snetproxy.NewMockReconnecter(ctrl)
		proxyConn := snetproxy.NewProxyConn(mockConn, mockReconnecter)
		mockIO := mock_snetproxy.NewMockIOOperation(ctrl)
		mockIO.EXPECT().IsWrite().Return(true).AnyTimes()
		Convey("IO must reconnect after dispatcher error, and do op on new conn", func() {
			connFromReconnect := NewMockConnWithAddrs(ctrl, localAddr, nil, bindAddr, addr.SvcNone)
			connFromReconnect.EXPECT().SetWriteDeadline(Any()).Return(nil).AnyTimes()
			connFromReconnect.EXPECT().SetReadDeadline(Any()).Return(nil).AnyTimes()
			gomock.InOrder(
				mockIO.EXPECT().Do(mockConn).Return(dispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).Return(connFromReconnect, nil),
				mockIO.EXPECT().Do(connFromReconnect).Return(nil),
			)
			err := proxyConn.DoIO(mockIO)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("IO must return a nil error if successful", func() {
			mockIO.EXPECT().Do(mockConn).Return(nil)
			err := proxyConn.DoIO(mockIO)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("IO must return non-dispatcher errors", func() {
			mockIO.EXPECT().Do(mockConn).Return(writeNonDispatcherError)
			err := proxyConn.DoIO(mockIO)
			SoMsg("err", common.GetErrorMsg(err), ShouldEqual,
				common.GetErrorMsg(writeNonDispatcherError))
		})
		Convey("IO must return an error if the reconnect changed addresses", func() {
			connFromReconnect := NewMockConnWithAddrs(ctrl,
				otherLocalAddr, nil, bindAddr, addr.SvcNone)
			gomock.InOrder(
				mockIO.EXPECT().Do(mockConn).Return(dispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).Return(connFromReconnect, nil),
			)
			err := proxyConn.DoIO(mockIO)
			SoMsg("err", common.GetErrorMsg(err), ShouldEqual, snetproxy.ErrLocalAddressChanged)
		})
		Convey("IO must return an error if reconnect got an error from the dispatcher", func() {
			// If reconnection failed while the dispatcher was up (e.g.,
			// requested port is no longer available, registration message was
			// malformed) the caller must be informed because reattempts will
			// probably get the same error again.
			gomock.InOrder(
				mockIO.EXPECT().Do(mockConn).Return(writeDispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).Return(nil, connectErrorFromDispatcher),
			)
			err := proxyConn.DoIO(mockIO)
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("IO returns dispatcher dead if write deadline reached when disconnected", func() {
			mockConn.EXPECT().SetWriteDeadline(Any()).Return(nil).AnyTimes()
			mockConn.EXPECT().SetReadDeadline(Any()).Return(nil).AnyTimes()
			gomock.InOrder(
				mockIO.EXPECT().Do(mockConn).Return(writeDispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).DoAndReturn(
					func(_ time.Duration) (snet.Conn, error) {
						time.Sleep(tickerMultiplier(4))
						return mockConn, nil
					}),
			)
			proxyConn.SetWriteDeadline(time.Now().Add(tickerMultiplier(2)))
			err := proxyConn.DoIO(mockIO)
			SoMsg("err", common.GetErrorMsg(err), ShouldEqual, snetproxy.ErrDispatcherDead)
		})
		Convey("SetWriteDeadline in the past unblocks a blocked writer", func() {
			mockConn.EXPECT().SetWriteDeadline(Any()).Return(nil).AnyTimes()
			mockConn.EXPECT().SetReadDeadline(Any()).Return(nil).AnyTimes()
			gomock.InOrder(
				mockIO.EXPECT().Do(mockConn).Return(writeDispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).DoAndReturn(
					func(_ time.Duration) (snet.Conn, error) {
						time.Sleep(tickerMultiplier(6))
						return mockConn, nil
					}),
			)
			// Set a deadline that is sufficient to Reconnect. We later move
			// the deadline in the past, thus cancelling the write prior to the
			// Reconnect completing.
			proxyConn.SetWriteDeadline(time.Now().Add(tickerMultiplier(10)))
			go func() {
				// Give write time to block on the existing deadline
				time.Sleep(tickerMultiplier(2))
				proxyConn.SetWriteDeadline(time.Now().Add(tickerMultiplier(-1)))
			}()
			err := proxyConn.DoIO(mockIO)
			SoMsg("err", common.GetErrorMsg(err), ShouldEqual, snetproxy.ErrDispatcherDead)
		})
		Convey("SetReadDeadline in the past unblocks a blocked reader", func() {
			mockConn.EXPECT().SetWriteDeadline(Any()).Return(nil).AnyTimes()
			mockConn.EXPECT().SetReadDeadline(Any()).Return(nil).AnyTimes()
			mockIO := mock_snetproxy.NewMockIOOperation(ctrl)
			mockIO.EXPECT().IsWrite().Return(false).AnyTimes()
			gomock.InOrder(
				mockIO.EXPECT().Do(mockConn).Return(writeDispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).DoAndReturn(
					func(_ time.Duration) (snet.Conn, error) {
						time.Sleep(tickerMultiplier(6))
						return mockConn, nil
					}),
			)
			// Set a deadline that is sufficient to Reconnect. We later move
			// the deadline in the past, thus cancelling the write prior to the
			// Reconnect completing.
			proxyConn.SetReadDeadline(time.Now().Add(tickerMultiplier(10)))
			go func() {
				// Give write time to block on the existing deadline
				time.Sleep(tickerMultiplier(2))
				proxyConn.SetReadDeadline(time.Now().Add(tickerMultiplier(-1)))
			}()
			err := proxyConn.DoIO(mockIO)
			SoMsg("err", common.GetErrorMsg(err), ShouldEqual, snetproxy.ErrDispatcherDead)
		})
		Convey("After reconnect, IO deadline is inherited by the new connection", func() {
			deadline := time.Now().Add(tickerMultiplier(1))
			connFromReconnect := NewMockConnWithAddrs(ctrl, localAddr, nil, bindAddr, addr.SvcNone)
			gomock.InOrder(
				mockConn.EXPECT().SetWriteDeadline(deadline).Return(nil),
				mockIO.EXPECT().Do(mockConn).Return(dispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).Return(connFromReconnect, nil),
				connFromReconnect.EXPECT().SetReadDeadline(time.Time{}).Return(nil),
				connFromReconnect.EXPECT().SetWriteDeadline(deadline).Return(nil),
				mockIO.EXPECT().Do(connFromReconnect).Return(nil),
			)
			proxyConn.SetWriteDeadline(deadline)
			proxyConn.DoIO(mockIO)
		})
	})
}

func TestProxyConnAddrs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	Convey("Given a proxy conn running on an underlying connection with a reconnecter", t, func() {
		mockConn := mock_snet.NewMockConn(ctrl)
		mockReconnecter := mock_snetproxy.NewMockReconnecter(ctrl)
		proxyConn := snetproxy.NewProxyConn(mockConn, mockReconnecter)
		Convey("Local address must call the same function on the underlying connection", func() {
			mockConn.EXPECT().LocalAddr().Return(localAddr)
			address := proxyConn.LocalAddr()
			SoMsg("address", address, ShouldEqual, localAddr)
		})
		Convey("Remote address must call the same function on the underlying connection", func() {
			mockConn.EXPECT().RemoteAddr().Return(remoteAddr)
			address := proxyConn.RemoteAddr()
			SoMsg("address", address, ShouldEqual, remoteAddr)
		})
		Convey("Bind address must call the same function on the underlying connection", func() {
			mockConn.EXPECT().BindAddr().Return(bindAddr)
			address := proxyConn.BindAddr()
			SoMsg("address", address, ShouldEqual, bindAddr)
		})
		Convey("SVC address must call the same function on the underlying connection", func() {
			mockConn.EXPECT().SVC().Return(svc)
			address := proxyConn.SVC()
			SoMsg("address", address, ShouldEqual, svc)
		})
	})
}

func TestProxyConnReadWrite(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	Convey("Given a proxy conn running on an underlying connection with a reconnecter", t, func() {
		mockConn := NewMockConnWithAddrs(ctrl, localAddr, nil, bindAddr, addr.SvcNone)
		mockReconnecter := mock_snetproxy.NewMockReconnecter(ctrl)
		proxyConn := snetproxy.NewProxyConn(mockConn, mockReconnecter)
		Convey("Writes on proxy conn must call the same function on the underlying conn", func() {
			buffer := []byte{1, 2, 3}
			Convey("Write", func() {
				mockConn.EXPECT().Write(buffer).Return(len(buffer), nil)
				n, err := proxyConn.Write(buffer)
				SoMsg("n", n, ShouldEqual, len(buffer))
				SoMsg("err", err, ShouldBeNil)
			})
			Convey("WriteTo", func() {
				mockConn.EXPECT().WriteTo(buffer, remoteAddr).Return(len(buffer), nil)
				n, err := proxyConn.WriteTo(buffer, remoteAddr)
				SoMsg("n", n, ShouldEqual, len(buffer))
				SoMsg("err", err, ShouldBeNil)
			})
			Convey("WriteToSCION", func() {
				mockConn.EXPECT().WriteToSCION(buffer, remoteAddr).Return(len(buffer), nil)
				n, err := proxyConn.WriteToSCION(buffer, remoteAddr)
				SoMsg("n", n, ShouldEqual, len(buffer))
				SoMsg("err", err, ShouldBeNil)
			})
		})
		Convey("Reads on proxy conn must call the same function on the underlying conn", func() {
			buffer := make([]byte, 3)
			readData := []byte{4, 5}
			Convey("Read", func() {
				mockReadFunc := func(b []byte) (int, error) {
					copy(b, readData)
					return len(readData), nil
				}
				mockConn.EXPECT().Read(buffer).DoAndReturn(mockReadFunc)
				n, err := proxyConn.Read(buffer)
				SoMsg("n", n, ShouldEqual, len(readData))
				SoMsg("buffer", buffer[:n], ShouldResemble, readData)
				SoMsg("err", err, ShouldBeNil)
			})

			mockReadFunc := func(b []byte) (int, *snet.Addr, error) {
				copy(b, readData)
				return len(readData), remoteAddr, nil
			}
			Convey("ReadFrom", func() {
				mockConn.EXPECT().ReadFrom(buffer).DoAndReturn(mockReadFunc)
				n, remoteAddress, err := proxyConn.ReadFrom(buffer)
				SoMsg("n", n, ShouldEqual, len(readData))
				SoMsg("address", remoteAddress, ShouldEqual, remoteAddr)
				SoMsg("buffer", buffer[:n], ShouldResemble, readData)
				SoMsg("err", err, ShouldBeNil)
			})
			Convey("ReadFromSCION", func() {
				mockConn.EXPECT().ReadFromSCION(buffer).DoAndReturn(mockReadFunc)
				n, remoteAddress, err := proxyConn.ReadFromSCION(buffer)
				SoMsg("n", n, ShouldEqual, len(readData))
				SoMsg("address", remoteAddress, ShouldEqual, remoteAddr)
				SoMsg("buffer", buffer[:n], ShouldResemble, readData)
				SoMsg("err", err, ShouldBeNil)
			})
		})
	})
}

func TestProxyConnClose(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	Convey("Given a proxy conn running on an underlying connection with a reconnecter", t, func() {
		mockConn := NewMockConnWithAddrs(ctrl, localAddr, nil, bindAddr, addr.SvcNone)
		mockReconnecter := mock_snetproxy.NewMockReconnecter(ctrl)
		proxyConn := snetproxy.NewProxyConn(mockConn, mockReconnecter)
		Convey("Calling close on proxy conn calls close on underlying conn", func() {
			mockReconnecter.EXPECT().Stop().AnyTimes()
			mockConn.EXPECT().Close()
			proxyConn := snetproxy.NewProxyConn(mockConn, mockReconnecter)
			proxyConn.Close()
		})
		Convey("Calling close while blocked in IO does not cause a reconnect attempt", func() {
			mockReconnecter.EXPECT().Stop().AnyTimes()
			mockIO := mock_snetproxy.NewMockIOOperation(ctrl)
			mockIO.EXPECT().IsWrite().Return(true).AnyTimes()
			mockIO.EXPECT().Do(mockConn).DoAndReturn(
				func(_ snet.Conn) error {
					time.Sleep(tickerMultiplier(2))
					return writeDispatcherError
				})
			mockConn.EXPECT().Close()
			go func() {
				proxyConn.DoIO(mockIO)
			}()
			time.Sleep(tickerMultiplier(1))
			proxyConn.Close()
			// Wait for mocked IO to finish (note that real IO would be
			// unblocked immediately by the go runtime)
			time.Sleep(tickerMultiplier(10))
		})
		Convey("Calling close while IO is blocked waiting for reconnect unblocks waiter", func() {
			mockReconnecter.EXPECT().Stop().AnyTimes()
			mockReconnecter.EXPECT().
				Reconnect(Any()).
				DoAndReturn(func(_ time.Duration) (snet.Conn, error) {
					select {}
				})
			mockIO := mock_snetproxy.NewMockIOOperation(ctrl)
			mockIO.EXPECT().IsWrite().Return(true).AnyTimes()
			mockIO.EXPECT().Do(mockConn).Return(writeDispatcherError)
			mockConn.EXPECT().Close()
			barrierCh := make(chan struct{})
			go func() {
				proxyConn.DoIO(mockIO)
				close(barrierCh)
			}()
			time.Sleep(tickerMultiplier(1))
			proxyConn.Close()
			select {
			case <-barrierCh:
			case <-time.After(tickerMultiplier(20)):
				t.Fatalf("goroutine took too long to finish")
			}
		})
		Convey("Calling close twice panics", func() {
			mockReconnecter.EXPECT().Stop().AnyTimes()
			mockConn.EXPECT().Close()
			proxyConn.Close()
			SoMsg("close panic", func() { proxyConn.Close() }, ShouldPanicWith, "double close")
		})
		Convey("Calling close shuts down the reconnecting goroutine (if any)", func() {
			mockReconnecter.EXPECT().Stop()
			mockConn.EXPECT().Close()
			proxyConn.Close()
		})
	})
}
