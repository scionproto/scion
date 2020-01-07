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

package ifstate

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
)

// TestPusherPush tests that if an interface is active the interface state info
// is pushed to all border routers.
func TestPusherPush(t *testing.T) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	topoProvider := itopotest.TopoProviderFromFile(t, "testdata/topology.json")
	msgr := mock_infra.NewMockMessenger(mctrl)
	intfs := NewInterfaces(topoProvider.Get().IFInfoMap(), Config{})
	p := PusherConf{
		TopoProvider: topoProvider,
		Intfs:        intfs,
		Msgr:         msgr,
	}.New()
	expectedMsg := &path_mgmt.IFStateInfos{
		Infos: []*path_mgmt.IFStateInfo{{
			IfID:   101,
			Active: true,
		}},
	}
	// When to expect a message being pushed.
	tests := map[State]bool{
		Active:  true,
		Revoked: false,
	}
	for state, expectMsg := range tests {
		t.Run(fmt.Sprintf("Interface state: %s", state), func(t *testing.T) {
			intfs.Get(101).state = state
			if expectMsg {
				for _, br := range topoProvider.Get().BRNames() {
					a := topoProvider.Get().SBRAddress(br)
					msgr.EXPECT().SendIfStateInfos(gomock.Any(), gomock.Eq(expectedMsg),
						gomock.Eq(a), gomock.Any())
				}
			}
			p.Push(context.Background(), 101)
		})
	}
}
