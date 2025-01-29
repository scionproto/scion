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

package dataplane_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/gateway/control/mock_control"
	"github.com/scionproto/scion/gateway/dataplane"
)

func TestAtomicRoutingTable(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	art := &dataplane.AtomicRoutingTable{}

	// Do not set any routing table yet
	assert.Nil(t, art.RouteIPv4(layers.IPv4{}))
	assert.Nil(t, art.RouteIPv6(layers.IPv6{}))

	// Use a mocked routing table
	rt := mock_control.NewMockRoutingTable(ctrl)
	assert.Nil(t, art.SetRoutingTable(rt))
	rt.EXPECT().RouteIPv4(layers.IPv4{})
	assert.Nil(t, art.RouteIPv4(layers.IPv4{}))
	rt.EXPECT().RouteIPv6(layers.IPv6{})
	assert.Nil(t, art.RouteIPv6(layers.IPv6{}))

	// Set routing table back to nil
	assert.Equal(t, rt, art.SetRoutingTable(nil))
	assert.Nil(t, art.RouteIPv4(layers.IPv4{}))
	assert.Nil(t, art.RouteIPv6(layers.IPv6{}))
}
