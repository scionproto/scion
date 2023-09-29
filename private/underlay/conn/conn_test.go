// Copyright 2023 ETH Zurich
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

package conn

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/private/xtest"
)

func TestNew(t *testing.T) {
	testCases := map[string]struct {
		addr *net.UDPAddr
	}{
		"undefined_addr": {
			addr: xtest.MustParseUDPAddr(t, "0.0.0.0:0"),
		},
		"undefined_port": {
			addr: xtest.MustParseUDPAddr(t, "127.0.0.1:0"),
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			sc, err := New(tc.addr, nil, &Config{
				SendBufferSize:    0,
				ReceiveBufferSize: 0,
			})
			require.NoError(t, err)
			defer sc.Close()
			lAddr := sc.LocalAddr()

			if tc.addr != nil && !tc.addr.IP.IsUnspecified() {
				assert.Equal(t, tc.addr.IP, lAddr.IP)
			}

			// Client
			cc, err := New(nil, lAddr, &Config{
				SendBufferSize:    0,
				ReceiveBufferSize: 0,
			})
			require.NoError(t, err)
			defer cc.Close()

			exchangeMessages := func(sc Conn, cc Conn) {
				msg := []byte("hello")

				go func() {
					_, err := cc.Write(msg)
					require.NoError(t, err)
				}()

				buf := make([]byte, 100)
				n, cAddr, err := sc.ReadFrom(buf)
				require.NoError(t, err)
				assert.Equal(t, msg, buf[:n])
				assert.Equal(t, cc.LocalAddr(), cAddr)
			}

			exchangeMessages(sc, cc)
		})
	}

}
