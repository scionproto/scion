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
	t.Log("Reconnections must conserve local and bind addresses")
	t.Log("Given a mocked underlying connection with local and bind")
	t.Log("Allocated ports are reused on subsequent attempts")

	localNoPortAddr := MustParseSnet("1-ff00:0:1,[192.168.0.1]:0")
	localPortAddr := MustParseSnet("1-ff00:0:1,[192.168.0.1]:80")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConn := mock_net.NewMockPacketConn(ctrl)

	md := mock_reliable.NewMockDispatcher(ctrl)
	network := reconnect.NewDispatcherService(md)

	want1 := localNoPortAddr.Host
	md.EXPECT().
		Register(context.Background(), localAddr.IA, want1, svc).
		Return(mockConn, uint16(80), nil)

	want2 := &addr.AppAddr{
		L3: localNoPortAddr.Host.Copy().L3,
		L4: 80,
	}

	md.EXPECT().
		Register(context.Background(), localPortAddr.IA, want2, svc).
		Return(mockConn, uint16(81), nil)

	packetConn, _, err := network.RegisterTimeout(context.Background(), localPortAddr.IA,
		localNoPortAddr.Host, svc)
	assert.NoError(t, err)
	_, x := packetConn.(*reconnect.PacketConn).Reconnect()
	assert.NoError(t, x)
}

func TestNetworkFatalError(t *testing.T) {
	t.Log("Given a network running over an underlying mocked network")
	t.Log("The network returns non-dispatcher dial errors from the mock")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockNetwork := mock_reliable.NewMockDispatcher(ctrl)
	mockNetwork.EXPECT().
		Register(Any(), Any(), Any(), Any()).
		Return(nil, uint16(0), serrors.New("my-dummy-error"))

	network := reconnect.NewDispatcherService(mockNetwork)
	_, _, err := network.Register(context.Background(), addr.IA{}, nil, addr.SvcNone)
	assert.EqualError(t, err, "my-dummy-error")
	// t.Run("The network returns non-dispatcher listen errors from the mock", func(t *testing.T) {
	// 	mockNetwork.EXPECT().
	// 		Register(Any(), Any(), Any(), Any()).
	// 		Return(nil, uint16(0), err)
	// 	_, _, err := network.Register(context.Background(), addr.IA{}, nil, addr.SvcNone)
	// 	assert.Error(t, err)
	// })
}

func TestNetworkDispatcherDeadError(t *testing.T) {
	t.Log("Listen and Dial should reattempt to connect on dispatcher down errors")

	dispatcherError := &net.OpError{Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	t.Run("Dial tries to reconnect if no timeout set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockNetwork := mock_reliable.NewMockDispatcher(ctrl)
		gomock.InOrder(
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), dispatcherError).
				Times(2), //TODO(karampok). whatever value here seems the test pass
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), nil),
		)

		network := reconnect.NewDispatcherService(mockNetwork)
		_, _, err := network.Register(context.Background(), addr.IA{}, nil, addr.SvcNone)
		assert.NoError(t, err)
	})

	t.Run("Dial only retries for limited time if timeout set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockNetwork := mock_reliable.NewMockDispatcher(ctrl)
		gomock.InOrder(
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), dispatcherError).
				MinTimes(2).MaxTimes(5),
		)

		network := reconnect.NewDispatcherService(mockNetwork)
		_, _, err := network.Register(ctxMultiplier(4), addr.IA{}, nil, addr.SvcNone)
		assert.EqualError(t, err, "timeout expired")
	})

	t.Run("Listen tries to reconnect if no timeout set", func(t *testing.T) {
		//TODO(karampok). how is different the listen from dial?
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockNetwork := mock_reliable.NewMockDispatcher(ctrl)
		gomock.InOrder(
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), dispatcherError).
				Times(2),
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), nil),
		)

		network := reconnect.NewDispatcherService(mockNetwork)
		_, _, err := network.Register(context.Background(), addr.IA{}, nil, addr.SvcNone)
		assert.NoError(t, err)
	})

	t.Run("Listen only retries for limited time if timeout set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockNetwork := mock_reliable.NewMockDispatcher(ctrl)
		gomock.InOrder(
			mockNetwork.EXPECT().
				Register(Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), dispatcherError).
				MinTimes(3).MaxTimes(5),
		)

		network := reconnect.NewDispatcherService(mockNetwork)
		_, _, err := network.Register(ctxMultiplier(4), addr.IA{}, nil, addr.SvcNone)
		assert.EqualError(t, err, "timeout expired")
	})
}
