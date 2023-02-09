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

package reconnect_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/private/mocks/net/mock_net"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/sock/reliable/reconnect"
	"github.com/scionproto/scion/pkg/sock/reliable/reconnect/mock_reconnect"
)

func TestPacketConnIO(t *testing.T) {
	Convey("Given an underlying connection, a reconnecter and an IO operation", t, func() {
		ctrl := gomock.NewController(&xtest.PanickingReporter{T: t})
		defer ctrl.Finish()
		mockConn := mock_net.NewMockPacketConn(ctrl)
		mockReconnecter := mock_reconnect.NewMockReconnecter(ctrl)
		packetConn := reconnect.NewPacketConn(mockConn, mockReconnecter)
		mockIO := mock_reconnect.NewMockIOOperation(ctrl)
		mockIO.EXPECT().IsWrite().Return(true).AnyTimes()
		Convey("IO must reconnect after dispatcher error, and do op on new conn", func() {
			connFromReconnect := mock_net.NewMockPacketConn(ctrl)
			connFromReconnect.EXPECT().SetWriteDeadline(Any()).Return(nil).AnyTimes()
			connFromReconnect.EXPECT().SetReadDeadline(Any()).Return(nil).AnyTimes()
			gomock.InOrder(
				mockIO.EXPECT().Do(mockConn).Return(dispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).Return(connFromReconnect, uint16(0), nil),
				mockIO.EXPECT().Do(connFromReconnect).Return(nil),
			)
			err := packetConn.DoIO(mockIO)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("IO must return a nil error if successful", func() {
			mockIO.EXPECT().Do(mockConn).Return(nil)
			err := packetConn.DoIO(mockIO)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("IO must return non-dispatcher errors", func() {
			mockIO.EXPECT().Do(mockConn).Return(writeNonDispatcherError)
			err := packetConn.DoIO(mockIO)
			assert.ErrorIs(t, err, writeNonDispatcherError)
		})
		Convey("IO must return an error if reconnect got an error from the dispatcher", func() {
			// If reconnection failed while the dispatcher was up (e.g.,
			// requested port is no longer available, registration message was
			// malformed) the caller must be informed because reattempts will
			// probably get the same error again.
			gomock.InOrder(
				mockIO.EXPECT().Do(mockConn).Return(writeDispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).
					Return(nil, uint16(0), connectErrorFromDispatcher),
			)
			err := packetConn.DoIO(mockIO)
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("IO returns dispatcher dead if write deadline reached when disconnected", func() {
			mockConn.EXPECT().SetWriteDeadline(Any()).Return(nil).AnyTimes()
			mockConn.EXPECT().SetReadDeadline(Any()).Return(nil).AnyTimes()
			gomock.InOrder(
				mockIO.EXPECT().Do(mockConn).Return(writeDispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).DoAndReturn(
					func(_ context.Context) (net.PacketConn, uint16, error) {
						time.Sleep(tickerMultiplier(4))
						return mockConn, uint16(0), nil
					}),
			)
			packetConn.SetWriteDeadline(time.Now().Add(tickerMultiplier(2)))
			err := packetConn.DoIO(mockIO)
			SoMsg("err", err, ShouldEqual, reconnect.ErrDispatcherDead)
		})
		Convey("SetWriteDeadline in the past unblocks a blocked writer", func() {
			mockConn.EXPECT().SetWriteDeadline(Any()).Return(nil).AnyTimes()
			mockConn.EXPECT().SetReadDeadline(Any()).Return(nil).AnyTimes()
			gomock.InOrder(
				mockIO.EXPECT().Do(mockConn).Return(writeDispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).DoAndReturn(
					func(_ context.Context) (net.PacketConn, uint16, error) {
						time.Sleep(tickerMultiplier(6))
						return mockConn, uint16(0), nil
					}),
			)
			// Set a deadline that is sufficient to Reconnect. We later move
			// the deadline in the past, thus cancelling the write prior to the
			// Reconnect completing.
			packetConn.SetWriteDeadline(time.Now().Add(tickerMultiplier(10)))
			go func() {
				// Give write time to block on the existing deadline
				time.Sleep(tickerMultiplier(2))
				packetConn.SetWriteDeadline(time.Now().Add(tickerMultiplier(-1)))
			}()
			err := packetConn.DoIO(mockIO)
			SoMsg("err", err, ShouldEqual, reconnect.ErrDispatcherDead)
		})
		Convey("SetReadDeadline in the past unblocks a blocked reader", func() {
			mockConn.EXPECT().SetWriteDeadline(Any()).Return(nil).AnyTimes()
			mockConn.EXPECT().SetReadDeadline(Any()).Return(nil).AnyTimes()
			mockIO := mock_reconnect.NewMockIOOperation(ctrl)
			mockIO.EXPECT().IsWrite().Return(false).AnyTimes()
			gomock.InOrder(
				mockIO.EXPECT().Do(mockConn).Return(writeDispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).DoAndReturn(
					func(_ context.Context) (net.PacketConn, uint16, error) {
						time.Sleep(tickerMultiplier(6))
						return mockConn, uint16(0), nil
					}),
			)
			// Set a deadline that is sufficient to Reconnect. We later move
			// the deadline in the past, thus cancelling the write prior to the
			// Reconnect completing.
			packetConn.SetReadDeadline(time.Now().Add(tickerMultiplier(10)))
			go func() {
				// Give write time to block on the existing deadline
				time.Sleep(tickerMultiplier(2))
				packetConn.SetReadDeadline(time.Now().Add(tickerMultiplier(-1)))
			}()
			err := packetConn.DoIO(mockIO)
			SoMsg("err", err, ShouldEqual, reconnect.ErrDispatcherDead)
		})
		Convey("After reconnect, IO deadline is inherited by the new connection", func() {
			deadline := time.Now().Add(tickerMultiplier(1))
			connFromReconnect := mock_net.NewMockPacketConn(ctrl)
			gomock.InOrder(
				mockConn.EXPECT().SetWriteDeadline(deadline).Return(nil),
				mockIO.EXPECT().Do(mockConn).Return(dispatcherError),
				mockReconnecter.EXPECT().Reconnect(Any()).Return(connFromReconnect, uint16(0), nil),
				connFromReconnect.EXPECT().SetReadDeadline(time.Time{}).Return(nil),
				connFromReconnect.EXPECT().SetWriteDeadline(deadline).Return(nil),
				mockIO.EXPECT().Do(connFromReconnect).Return(nil),
			)
			packetConn.SetWriteDeadline(deadline)
			packetConn.DoIO(mockIO)
		})
	})
}

func TestPacketConnAddrs(t *testing.T) {
	Convey("Given a packet conn running on an underlying connection with a reconnecter", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockConn := mock_net.NewMockPacketConn(ctrl)
		mockReconnecter := mock_reconnect.NewMockReconnecter(ctrl)
		packetConn := reconnect.NewPacketConn(mockConn, mockReconnecter)
		Convey("Local address must call the same function on the underlying connection", func() {
			mockConn.EXPECT().LocalAddr().Return(localAddr)
			address := packetConn.LocalAddr()
			SoMsg("address", address, ShouldEqual, localAddr)
		})
	})
}

func TestPacketConnReadWrite(t *testing.T) {
	Convey("Given a packet conn running on an underlying connection with a reconnecter", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockConn := mock_net.NewMockPacketConn(ctrl)
		mockReconnecter := mock_reconnect.NewMockReconnecter(ctrl)
		packetConn := reconnect.NewPacketConn(mockConn, mockReconnecter)
		Convey("Writes on packet conn must call the same function on the underlying conn", func() {
			buffer := []byte{1, 2, 3}
			Convey("WriteTo", func() {
				mockConn.EXPECT().WriteTo(buffer, remoteAddr).Return(len(buffer), nil)
				n, err := packetConn.WriteTo(buffer, remoteAddr)
				SoMsg("n", n, ShouldEqual, len(buffer))
				SoMsg("err", err, ShouldBeNil)
			})
		})
		Convey("Reads on packet conn must call the same function on the underlying conn", func() {
			buffer := make([]byte, 3)
			readData := []byte{4, 5}
			mockReadFunc := func(b []byte) (int, *snet.UDPAddr, error) {
				copy(b, readData)
				return len(readData), remoteAddr, nil
			}
			Convey("ReadFrom", func() {
				mockConn.EXPECT().ReadFrom(buffer).DoAndReturn(mockReadFunc)
				n, remoteAddress, err := packetConn.ReadFrom(buffer)
				SoMsg("n", n, ShouldEqual, len(readData))
				SoMsg("address", remoteAddress, ShouldEqual, remoteAddr)
				SoMsg("buffer", buffer[:n], ShouldResemble, readData)
				SoMsg("err", err, ShouldBeNil)
			})
		})
	})
}

func TestPacketConnConcurrentReadWrite(t *testing.T) {
	Convey("Given a server blocked in reading, writes still go through", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockConn := mock_net.NewMockPacketConn(ctrl)
		mockReconnecter := mock_reconnect.NewMockReconnecter(ctrl)
		packetConn := reconnect.NewPacketConn(mockConn, mockReconnecter)
		mockConn.EXPECT().ReadFrom(Any()).DoAndReturn(
			func(_ []byte) (int, net.Addr, error) {
				// Keep the read blocked "forever"
				time.Sleep(tickerMultiplier(50))
				return 3, nil, nil
			},
		)
		mockConn.EXPECT().WriteTo(Any(), Any())

		barrierCh := make(chan struct{})
		go func() {
			buffer := make([]byte, 3)
			packetConn.ReadFrom(buffer)
		}()
		time.Sleep(tickerMultiplier(2))
		go func() {
			packetConn.WriteTo(testBuffer, nil)
			close(barrierCh)
		}()
		xtest.AssertReadReturnsBefore(t, barrierCh, tickerMultiplier(3))
	})
}

func TestPacketConnClose(t *testing.T) {
	Convey("Given a packet conn running on an underlying connection with a reconnecter", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockConn := mock_net.NewMockPacketConn(ctrl)
		mockReconnecter := mock_reconnect.NewMockReconnecter(ctrl)
		packetConn := reconnect.NewPacketConn(mockConn, mockReconnecter)
		Convey("Calling close on packet conn calls close on underlying conn", func() {
			mockReconnecter.EXPECT().Stop().AnyTimes()
			mockConn.EXPECT().Close()
			packetConn := reconnect.NewPacketConn(mockConn, mockReconnecter)
			packetConn.Close()
		})
		Convey("Calling close while blocked in IO does not cause a reconnect attempt", func() {
			mockReconnecter.EXPECT().Stop().AnyTimes()
			mockIO := mock_reconnect.NewMockIOOperation(ctrl)
			mockIO.EXPECT().IsWrite().Return(true).AnyTimes()
			mockIO.EXPECT().Do(mockConn).DoAndReturn(
				func(_ net.PacketConn) error {
					time.Sleep(tickerMultiplier(2))
					return writeDispatcherError
				})
			mockConn.EXPECT().Close()
			go func() {
				packetConn.DoIO(mockIO)
			}()
			time.Sleep(tickerMultiplier(1))
			packetConn.Close()
			// Wait for mocked IO to finish (note that real IO would be
			// unblocked immediately by the go runtime)
			time.Sleep(tickerMultiplier(10))
		})
		Convey("Calling close while IO is blocked waiting for reconnect unblocks waiter", func() {
			mockReconnecter.EXPECT().Stop().AnyTimes()
			mockReconnecter.EXPECT().
				Reconnect(Any()).
				DoAndReturn(func(_ context.Context) (net.PacketConn, uint16, error) {
					select {}
				})
			mockIO := mock_reconnect.NewMockIOOperation(ctrl)
			mockIO.EXPECT().IsWrite().Return(true).AnyTimes()
			mockIO.EXPECT().Do(mockConn).Return(writeDispatcherError)
			mockConn.EXPECT().Close()
			barrierCh := make(chan struct{})
			go func() {
				packetConn.DoIO(mockIO)
				close(barrierCh)
			}()
			time.Sleep(tickerMultiplier(1))
			packetConn.Close()
			select {
			case <-barrierCh:
			case <-time.After(tickerMultiplier(20)):
				t.Fatalf("goroutine took too long to finish")
			}
		})
		Convey("Calling close twice panics", func() {
			mockReconnecter.EXPECT().Stop().AnyTimes()
			mockConn.EXPECT().Close()
			packetConn.Close()
			SoMsg("close panic", func() { packetConn.Close() }, ShouldPanicWith, "double close")
		})
		Convey("Calling close shuts down the reconnecting goroutine (if any)", func() {
			mockReconnecter.EXPECT().Stop()
			mockConn.EXPECT().Close()
			packetConn.Close()
		})
	})
}
