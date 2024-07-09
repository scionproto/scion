// Copyright 2020 Anapaya Systems
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

package grpc_test

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/gateway/control/grpc"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/mocks/net/mock_net"
	"github.com/scionproto/scion/pkg/private/serrors"
	gpb "github.com/scionproto/scion/pkg/proto/gateway"
	"github.com/scionproto/scion/pkg/snet"
)

func TestControlDispatcher(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	src := &snet.UDPAddr{IA: addr.MustParseIA("1-ff00:0:110")}

	requests := make([][]byte, 3)
	for i := range requests {
		request, err := proto.Marshal(&gpb.ControlRequest{
			Request: &gpb.ControlRequest_Probe{
				Probe: &gpb.ProbeRequest{
					Data:      []byte("data" + strconv.Itoa(i)),
					SessionId: uint32(i),
				},
			},
		})
		require.NoError(t, err)
		requests[i] = request
	}

	// Put garbage.
	requests = append(requests, []byte("lol"))

	conn := mock_net.NewMockPacketConn(ctrl)
	for _, raw := range requests {
		raw := raw
		conn.EXPECT().ReadFrom(gomock.Any()).DoAndReturn(
			func(buf []byte) (int, net.Addr, error) {
				copy(buf, raw)
				return len(raw), src, nil
			},
		)
	}
	for _, raw := range requests[:3] {
		raw := raw
		// Use the fact that protobuf serializes this to the same wire format.
		conn.EXPECT().WriteTo(raw, src)
	}

	allReceived := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	conn.EXPECT().ReadFrom(gomock.Any()).DoAndReturn(
		func(buf []byte) (int, net.Addr, error) {
			close(allReceived)
			<-ctx.Done()
			return 0, nil, serrors.New("closed")
		},
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		err := (&grpc.ProbeDispatcher{}).Listen(ctx, conn)
		assert.NoError(t, err)
	}()

	// Wait for dispatcher to process all messages.
	<-allReceived
	cancel()

	// Make sure that the dispatcher shuts down.
	<-done

}
