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

package control_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
)

const (
	reportingInterval = 20 * time.Millisecond
	expiryInterval    = 100 * time.Millisecond
)

var (
	ia1      = addr.MustParseIA("1-ff00:0:110")
	ia2      = addr.MustParseIA("1-ff00:0:111")
	gateway1 = control.Gateway{Control: &net.UDPAddr{IP: []byte{1, 2, 3, 4}, Port: 12345}}
	gateway2 = control.Gateway{Control: &net.UDPAddr{IP: []byte{5, 6, 7, 8}, Port: 54321}}
	gateway3 = control.Gateway{Control: &net.UDPAddr{IP: []byte{10, 11, 12, 13}, Port: 23456}}
)

func TestAggregator(t *testing.T) {
	prefix1 := xtest.MustParseCIDR(t, "192.168.0.0/24")
	prefix2 := xtest.MustParseCIDR(t, "192.168.100.128/25")
	prefix3 := xtest.MustParseCIDR(t, "10.0.0.0/8")

	updateChan := make(chan (control.RemoteGateways), 10)
	a := control.Aggregator{
		RoutingUpdateChan: updateChan,
		ReportingInterval: reportingInterval,
		ExpiryInterval:    expiryInterval,
	}

	// Test adding prefixes before run is called.
	err := a.Prefixes(ia1, gateway1, []*net.IPNet{prefix1, prefix2})
	require.NoError(t, err)

	err = a.Run(context.Background())
	require.NoError(t, err)
	defer a.Close(context.Background())

	// Test adding some more prefixes.
	err = a.Prefixes(ia2, gateway2, []*net.IPNet{prefix3})
	require.NoError(t, err)
	err = a.Prefixes(ia1, gateway3, []*net.IPNet{})
	require.NoError(t, err)
	ru := <-updateChan
	expected := control.RemoteGateways{
		Gateways: map[addr.IA][]control.RemoteGateway{
			ia1: {
				control.RemoteGateway{
					Gateway:  gateway1,
					Prefixes: []*net.IPNet{prefix1, prefix2},
				},
				control.RemoteGateway{
					Gateway:  gateway3,
					Prefixes: []*net.IPNet{},
				},
			},
			ia2: {
				control.RemoteGateway{
					Gateway:  gateway2,
					Prefixes: []*net.IPNet{prefix3},
				},
			},
		},
	}
	require.Equal(t, expected, ru)

	// Test updating prefixes for one Gateway.
	err = a.Prefixes(ia1, gateway1, []*net.IPNet{prefix1})
	require.NoError(t, err)
	ru = <-updateChan
	expected = control.RemoteGateways{
		Gateways: map[addr.IA][]control.RemoteGateway{
			ia1: {
				control.RemoteGateway{
					Gateway:  gateway1,
					Prefixes: []*net.IPNet{prefix1},
				},
				control.RemoteGateway{
					Gateway:  gateway3,
					Prefixes: []*net.IPNet{},
				},
			},
			ia2: {
				control.RemoteGateway{
					Gateway:  gateway2,
					Prefixes: []*net.IPNet{prefix3},
				},
			},
		},
	}
	require.Equal(t, expected, ru)

	// Test that entries are removed after the expiry interval.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start a go routine that periodically checks the updates.
	// If it is empty we exit and set the gotExpected counter to 1.
	var gotExpected int32
	go func() {
		for {
			select {
			case ru := <-updateChan:
				if len(ru.Gateways) == 0 {
					atomic.StoreInt32(&gotExpected, 1)
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for gotExpected to become one. Give some leeway for slow
	// environments, e.g., CI.
	require.Eventually(
		t,
		func() bool { return atomic.LoadInt32(&gotExpected) != 0 },
		10*expiryInterval,
		reportingInterval,
	)
}
