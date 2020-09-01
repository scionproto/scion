// Copyright 2019 Anapaya Systems
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

package ifstate_test

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/ifstate/mock_ifstate"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
)

// TestPusherPush tests that if an interface is active the interface state info
// is pushed to all border routers.
func TestPusherPush(t *testing.T) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	topoProvider := itopotest.TopoProviderFromFile(t, "testdata/topology.json")
	sender := mock_ifstate.NewMockInterfaceStateSender(mctrl)
	intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
	p := ifstate.PusherConf{
		TopoProvider: topoProvider,
		Intfs:        intfs,
		StateSender:  sender,
	}.New()
	expectedMsg := []ifstate.InterfaceState{{ID: 101}}
	// When to expect a message being pushed.
	tests := map[ifstate.State]bool{
		ifstate.Active:  true,
		ifstate.Revoked: false,
	}
	for state, expectMsg := range tests {
		t.Run(fmt.Sprintf("Interface state: %s", state), func(t *testing.T) {
			intfs.Get(101).SetState(state)
			if expectMsg {
				for _, br := range topoProvider.Get().BRNames() {
					brInfo, _ := topoProvider.Get().BR(br)
					a := brInfo.CtrlAddrs.SCIONAddress
					tcpA := &net.TCPAddr{IP: a.IP, Port: a.Port, Zone: a.Zone}
					sender.EXPECT().SendStateUpdate(gomock.Any(), expectedMsg, tcpA)
				}
			}
			p.Push(context.Background(), 101)
		})
	}
}
