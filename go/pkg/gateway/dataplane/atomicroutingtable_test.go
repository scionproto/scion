// Copyright 2020 Anapaya Systems

package dataplane_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/pkg/gateway/control/mock_control"
	"github.com/scionproto/scion/go/pkg/gateway/dataplane"
)

func TestAtomicRoutingTable(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	art := &dataplane.AtomicRoutingTable{}

	// Do not set any routing table yet
	assert.Nil(t, art.RouteIPv4(layers.IPv4{}))
	assert.Nil(t, art.RouteIPv6(layers.IPv6{}))
	assert.NotPanics(t, func() { art.AddRoute(1, nil) })

	// Use a mocked routing table
	rt := mock_control.NewMockRoutingTable(ctrl)
	art.SetRoutingTable(rt)
	rt.EXPECT().RouteIPv4(layers.IPv4{})
	assert.Nil(t, art.RouteIPv4(layers.IPv4{}))
	rt.EXPECT().RouteIPv6(layers.IPv6{})
	assert.Nil(t, art.RouteIPv6(layers.IPv6{}))
	rt.EXPECT().AddRoute(1, nil)
	assert.NotPanics(t, func() { art.AddRoute(1, nil) })

	// Set routing table back to nil
	art.SetRoutingTable(nil)
	assert.Nil(t, art.RouteIPv4(layers.IPv4{}))
	assert.Nil(t, art.RouteIPv6(layers.IPv6{}))
	assert.NotPanics(t, func() { art.AddRoute(1, nil) })
}
