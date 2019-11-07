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

package reliable

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/mocks/net/mock_net"
)

func TestReadPacketizer(t *testing.T) {
	// FIXME(scrye): This will get deleted when we move from to SEQPACKET.
	t.Run("Packetizer should extract multiple packets from an input stream", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		data := []byte{
			0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 1,
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			0, 80, 42,
			0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 1,
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			0, 80, 42,
		}
		conn := mock_net.NewMockConn(ctrl)
		conn.EXPECT().Read(gomock.Any()).DoAndReturn(
			func(b []byte) (int, error) {
				max := 5
				if max > len(data) {
					max = len(data)
				}
				n := copy(b, data[:max])
				data = data[n:]
				return n, nil
			}).AnyTimes()
		packetizer := NewReadPacketizer(conn)
		b := make([]byte, 128)
		n, err := packetizer.Read(b)
		assert.NoError(t, err, "first packet err")
		assert.Equal(t, 32, n, "first packet size")
		n, err = packetizer.Read(b)
		assert.NoError(t, err, "second packet err")
		assert.Equal(t, 32, n, "second packet err")
	})
}

func TestWriteStreamer(t *testing.T) {
	// FIXME(scrye): This will get deleted when we move from to SEQPACKET.
	t.Run("Streamer should do repeated calls to send a full message", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		conn := mock_net.NewMockConn(ctrl)
		gomock.InOrder(
			conn.EXPECT().Write([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}).Return(4, nil),
			conn.EXPECT().Write([]byte{5, 6, 7, 8, 9, 10}).Return(4, nil),
			conn.EXPECT().Write([]byte{9, 10}).Return(2, nil),
		)
		streamer := NewWriteStreamer(conn)
		err := streamer.Write(data)
		assert.NoError(t, err)
	})
}
