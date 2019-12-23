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
	"os"
	"syscall"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/mocks/net/mock_net"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/sock/reliable/mock_reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
)

func TestReconnect(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDispatcher := mock_reliable.NewMockDispatcher(ctrl)
	t.Run("Given a mocked underlying connection with local and bind", func(t *testing.T) {
		mockConn := mock_net.NewMockPacketConn(ctrl)
		mockDispatcher.EXPECT().
			Register(context.Background(), localAddr.IA,
				localNoPortAddr.ToNetUDPAddr(), svc).
			Return(mockConn, uint16(80), nil)

		want := &net.UDPAddr{
			IP:   localNoPortAddr.Host.Copy().L3.IP(),
			Port: 80,
		}

		mockDispatcher.EXPECT().
			Register(context.Background(), localAddr.IA, want, svc).
			Return(mockConn, uint16(80), nil)

		network := reconnect.NewDispatcher(mockDispatcher)
		packetConn, _, _ := network.RegisterTimeout(context.Background(), localAddr.IA,
			localNoPortAddr.ToNetUDPAddr(), svc)
		packetConn.(*reconnect.PacketConn).Reconnect()
	})
}

func TestNetworkFatalError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := serrors.New("my-dummy-error")
	mockNetwork := mock_reliable.NewMockDispatcher(ctrl)
	network := reconnect.NewDispatcher(mockNetwork)
	t.Run("The network returns non-dispatcher register errors from the mock", func(t *testing.T) {
		mockNetwork.EXPECT().
			Register(Any(), Any(), Any(), Any()).
			Return(nil, uint16(0), err)
		_, _, err := network.Register(context.Background(), addr.IA{}, nil, addr.SvcNone)
		assert.EqualError(t, err, "my-dummy-error")
	})
}

func TestNetworkDispatcherDeadError(t *testing.T) {
	dispatcherError := &net.OpError{Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	t.Log("Listen and Dial should reattempt to connect on dispatcher down errors")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNetwork := mock_reliable.NewMockDispatcher(ctrl)
	network := reconnect.NewDispatcher(mockNetwork)
	t.Run("Dial tries to reconnect if no timeout set", func(t *testing.T) {
		mockConn := mock_net.NewMockPacketConn(ctrl)
		gomock.InOrder(
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), dispatcherError).
				Times(2),
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(mockConn, uint16(0), nil),
		)
		_, _, err := network.Register(context.Background(), addr.IA{}, nil, addr.SvcNone)
		assert.NoError(t, err)
	})
	t.Run("Dial only retries for limited time if timeout set", func(t *testing.T) {
		gomock.InOrder(
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), dispatcherError).
				MinTimes(2).MaxTimes(5),
		)
		_, _, err := network.Register(ctxMultiplier(4), addr.IA{}, nil, addr.SvcNone)
		assert.EqualError(t, err, "timeout expired")
	})
	t.Run("Listen tries to reconnect if no timeout set", func(t *testing.T) {
		mockConn := mock_net.NewMockPacketConn(ctrl)
		gomock.InOrder(
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), dispatcherError).
				Times(2),
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(mockConn, uint16(0), nil),
		)
		_, _, err := network.Register(context.Background(), addr.IA{}, nil, addr.SvcNone)
		assert.NoError(t, err)
	})
	t.Run("Listen only retries for limited time if timeout set", func(t *testing.T) {
		gomock.InOrder(
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), dispatcherError).
				MinTimes(3).MaxTimes(5),
		)
		_, _, err := network.Register(ctxMultiplier(4), addr.IA{}, nil, addr.SvcNone)
		assert.EqualError(t, err, "timeout expired")
	})
}
