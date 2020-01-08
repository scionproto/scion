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
	"sort"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestHandler(t *testing.T) {
	topoProvider := itopotest.TopoProviderFromFile(t, "testdata/topology.json")

	type testDef struct {
		name     string
		req      *path_mgmt.IFStateReq
		expected *path_mgmt.IFStateInfos
		result   *infra.HandlerResult
	}

	rev102, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
		IfID: 102,
	}, infra.NullSigner)
	xtest.FailOnErr(t, err)

	tests := []testDef{
		{
			name: "Request single, active",
			req:  &path_mgmt.IFStateReq{IfID: 101},
			expected: &path_mgmt.IFStateInfos{
				Infos: []*path_mgmt.IFStateInfo{
					{IfID: 101, Active: true},
				},
			},
		},
		{
			name: "Request all, all active",
			req:  &path_mgmt.IFStateReq{},
			expected: &path_mgmt.IFStateInfos{
				Infos: []*path_mgmt.IFStateInfo{
					{IfID: 100, Active: true},
					{IfID: 101, Active: true},
					{IfID: 102, Active: true},
					{IfID: 103, Active: true},
					{IfID: 104, Active: true},
					{IfID: 105, Active: true},
				},
			},
		},
		{
			name: "Request all, one revoked, one inactive",
			req:  &path_mgmt.IFStateReq{},
			expected: &path_mgmt.IFStateInfos{
				Infos: []*path_mgmt.IFStateInfo{
					{IfID: 100, Active: true},
					{IfID: 101, Active: true},
					{IfID: 102, Active: false, SRevInfo: rev102},
					{IfID: 103, Active: true},
					{IfID: 104, Active: true},
					{IfID: 105, Active: false},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			rw := mock_infra.NewMockResponseWriter(mctrl)
			var reply *path_mgmt.IFStateInfos
			rw.EXPECT().SendIfStateInfoReply(gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, msg *path_mgmt.IFStateInfos) error {
					reply = msg
					return nil
				})
			h := NewHandler(interfaces(t, topoProvider, test.expected))
			serveCtx := infra.NewContextWithResponseWriter(context.Background(), rw)
			req := infra.NewRequest(serveCtx, test.req, nil, nil, 0)
			handlerRes := h.Handle(req)
			assert.Equal(t, infra.MetricsResultOk, handlerRes)
			sort.Slice(reply.Infos, func(i, j int) bool {
				return reply.Infos[i].IfID < reply.Infos[j].IfID
			})
			assert.Equal(t, test.expected, reply)
		})
	}
}

func interfaces(t *testing.T, topoProvider topology.Provider,
	expectedIfSate *path_mgmt.IFStateInfos) *Interfaces {

	intfs := NewInterfaces(topoProvider.Get().IFInfoMap(), Config{})
	activateAll(intfs)
	for _, info := range expectedIfSate.Infos {
		if !info.Active {
			intf := intfs.Get(info.IfID)
			intf.SetState(Revoked)
			if info.SRevInfo != nil {
				require.NoError(t, intf.SetRevocation(info.SRevInfo))
			}
		}
	}
	return intfs
}
