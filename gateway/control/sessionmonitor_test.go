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
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/control/mock_control"
	"github.com/scionproto/scion/gateway/pathhealth"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/mocks/net/mock_net"
	gatewaypb "github.com/scionproto/scion/pkg/proto/gateway"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

type pktMatcher struct {
	raw         []byte
	description string
}

// Matches returns whether x is a match.
func (m pktMatcher) Matches(x any) bool {
	other, ok := x.([]byte)
	if !ok {
		return false
	}
	return bytes.Equal(m.raw, other)
}

// String describes what the matcher matches.
func (m pktMatcher) String() string {
	return fmt.Sprintf("packet %s", m.description)
}

func matchPkt(t *testing.T, pkt *gatewaypb.ControlRequest) gomock.Matcher {
	raw, err := proto.Marshal(pkt)
	require.NoError(t, err)
	return pktMatcher{raw: raw, description: pkt.String()}
}

type udpAddrMatcher struct {
	a *snet.UDPAddr
}

// Matches returns whether x is a match.
func (m udpAddrMatcher) Matches(x any) bool {
	other, ok := x.(*snet.UDPAddr)
	if !ok {
		return false
	}
	return reflect.DeepEqual(m.a, other)
}

// String describes what the matcher matches.
func (m udpAddrMatcher) String() string {
	return m.a.String()
}

func TestSessionMonitorTestProbing(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	conn := mock_net.NewMockPacketConn(ctrl)
	pathReg := mock_control.NewMockPathMonitorRegistration(ctrl)
	sessMon := control.SessionMonitor{
		ID:               25,
		RemoteIA:         addr.MustParseIA("1-ff00:0:110"),
		ProbeAddr:        &net.UDPAddr{IP: net.IP{10, 0, 01}, Port: 42},
		Events:           make(chan control.SessionEvent, 50),
		ProbeConn:        conn,
		HealthExpiration: time.Hour,
		Paths:            pathReg,
		ProbeInterval:    5 * time.Microsecond,
	}
	path := mock_snet.NewMockPath(ctrl)
	path.EXPECT().Dataplane().Return(snetpath.SCION{Raw: []byte("dummy")}).AnyTimes()
	path.EXPECT().UnderlayNextHop().AnyTimes()
	pathReg.EXPECT().Get().Return(pathhealth.Selection{Paths: []snet.Path{path}}).Times(3)
	pathReg.EXPECT().Get().Return(pathhealth.Selection{}).AnyTimes()
	conn.EXPECT().WriteTo(matchPkt(t, &gatewaypb.ControlRequest{
		Request: &gatewaypb.ControlRequest_Probe{
			Probe: &gatewaypb.ProbeRequest{
				SessionId: uint32(sessMon.ID),
			},
		},
	}), udpAddrMatcher{
		a: &snet.UDPAddr{
			IA:      sessMon.RemoteIA,
			Host:    sessMon.ProbeAddr,
			NextHop: path.UnderlayNextHop(),
			Path:    path.Dataplane(),
		},
	}).Times(3)
	conn.EXPECT().ReadFrom(gomock.Any()).AnyTimes()
	errChan := make(chan error)
	go func() {
		errChan <- sessMon.Run(context.Background())
	}()

	time.Sleep(50 * time.Millisecond)
	err := sessMon.Close(context.Background())
	assert.NoError(t, err)

	select {
	case <-time.After(time.Second):
		t.Fatalf("Test timed out")
	case err := <-errChan:
		assert.NoError(t, err)
	}
	assert.Empty(t, sessMon.Events)
}

func TestSessionMonitorTestEvents(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	conn := mock_net.NewMockPacketConn(ctrl)
	events := make(chan control.SessionEvent, 50)
	pathReg := mock_control.NewMockPathMonitorRegistration(ctrl)
	pathReg.EXPECT().Get().Return(pathhealth.Selection{}).AnyTimes()
	sessMon := control.SessionMonitor{
		ID:               25,
		RemoteIA:         addr.MustParseIA("1-ff00:0:110"),
		ProbeAddr:        &net.UDPAddr{IP: net.IP{10, 0, 01}, Port: 42},
		Events:           events,
		ProbeConn:        conn,
		HealthExpiration: time.Millisecond,
		Paths:            pathReg,
		ProbeInterval:    time.Hour,
	}

	probeResponse := &gatewaypb.ControlResponse{
		Response: &gatewaypb.ControlResponse_Probe{
			Probe: &gatewaypb.ProbeResponse{
				SessionId: uint32(sessMon.ID),
			},
		},
	}
	rawResponse, err := proto.Marshal(probeResponse)
	require.NoError(t, err)

	readReturn := make(chan struct{}, 10)

	conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).AnyTimes()
	conn.EXPECT().ReadFrom(gomock.Any()).DoAndReturn(func(buf []byte) (int, net.Addr, error) {
		<-readReturn
		copy(buf, rawResponse)
		return len(rawResponse), nil, nil
	}).AnyTimes()

	errChan := make(chan error)
	go func() {
		errChan <- sessMon.Run(context.Background())
	}()

	readReturn <- struct{}{}
	readReturn <- struct{}{}
	readReturn <- struct{}{}
	select {
	case <-time.After(time.Second):
		t.Fatalf("Test timed out")
	case event := <-events:
		assert.Equal(t, control.EventUp, event.Event)
	}
	assert.Empty(t, events)

	// now wait for the down event if no packets are received for a long time.
	select {
	case <-time.After(time.Second):
		t.Fatalf("Test timed out")
	case event := <-events:
		assert.Equal(t, control.EventDown, event.Event)
	}
	assert.Empty(t, events)

	// send some packets again to check the session recovers.
	readReturn <- struct{}{}
	readReturn <- struct{}{}
	readReturn <- struct{}{}
	select {
	case <-time.After(time.Second):
		t.Fatalf("Test timed out")
	case event := <-events:
		assert.Equal(t, control.EventUp, event.Event)
	}
	assert.Empty(t, events)

	err = sessMon.Close(context.Background())
	assert.NoError(t, err)

	select {
	case <-time.After(time.Second):
		t.Fatalf("Test timed out")
	case err := <-errChan:
		assert.NoError(t, err)
	}

}
