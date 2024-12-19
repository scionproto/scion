// Copyright 2021 Anapaya Systems
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

package mgmtapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/ptr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/router/control"
	"github.com/scionproto/scion/router/control/mock_api"
)

var update = xtest.UpdateGoldenFiles()

func TestAPI(t *testing.T) {
	testCases := map[string]struct {
		Handler            func(t *testing.T, ctrl *gomock.Controller) http.Handler
		RequestURL         string
		ResponseFile       string
		Status             int
		IgnoreResponseBody bool
	}{
		"interfaces": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				dataplane := mock_api.NewMockObservableDataplane(ctrl)
				s := &Server{
					Dataplane: dataplane,
				}
				dataplane.EXPECT().ListInternalInterfaces().Return(
					createInternalIntfs(t), nil,
				)
				dataplane.EXPECT().ListExternalInterfaces().Return(
					createExternalIntfs(t), nil,
				)
				dataplane.EXPECT().ListSiblingInterfaces().Return(
					createSiblingIntfs(t), nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/interfaces.json",
			RequestURL:   "/interfaces",
			Status:       200,
		},
		"interfaces external error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				dataplane := mock_api.NewMockObservableDataplane(ctrl)
				s := &Server{
					Dataplane: dataplane,
				}
				dataplane.EXPECT().ListInternalInterfaces().Return(
					createInternalIntfs(t), nil,
				)
				dataplane.EXPECT().ListExternalInterfaces().Return(
					nil, serrors.New("internal"),
				)
				return Handler(s)
			},
			RequestURL:   "/interfaces",
			ResponseFile: "testdata/interfaces-external-error.json",
			Status:       500,
		},
		"interfaces internal error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				dataplane := mock_api.NewMockObservableDataplane(ctrl)
				s := &Server{
					Dataplane: dataplane,
				}
				dataplane.EXPECT().ListInternalInterfaces().Return(
					nil, serrors.New("internal"),
				)

				return Handler(s)
			},
			RequestURL:   "/interfaces",
			ResponseFile: "testdata/interfaces-internal-error.json",
			Status:       500,
		},
		"interfaces siblings error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				dataplane := mock_api.NewMockObservableDataplane(ctrl)
				s := &Server{
					Dataplane: dataplane,
				}
				dataplane.EXPECT().ListInternalInterfaces().Return(
					createInternalIntfs(t), nil,
				)
				dataplane.EXPECT().ListExternalInterfaces().Return(
					createExternalIntfs(t), nil,
				)
				dataplane.EXPECT().ListSiblingInterfaces().Return(
					nil, serrors.New("internal"),
				)
				return Handler(s)
			},
			RequestURL:   "/interfaces",
			ResponseFile: "testdata/interfaces-sibling-error.json",
			Status:       500,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			req, err := http.NewRequest("GET", tc.RequestURL, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			tc.Handler(t, ctrl).ServeHTTP(rr, req)

			assert.Equal(t, tc.Status, rr.Result().StatusCode)

			if tc.IgnoreResponseBody {
				return
			}
			if *update {
				require.NoError(t, os.WriteFile(tc.ResponseFile, rr.Body.Bytes(), 0666))
			}
			golden, err := os.ReadFile(tc.ResponseFile)
			require.NoError(t, err)
			assert.Equal(t, string(golden), rr.Body.String())
		})
	}
}

func createExternalIntfs(t *testing.T) []control.ExternalInterface {
	return []control.ExternalInterface{
		{
			IfID: 1,
			Link: control.LinkInfo{
				Local: control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Addr: netip.MustParseAddrPort("172.20.0.3:50000"),
				},
				Remote: control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:111"),
					Addr: netip.MustParseAddrPort("172.20.0.2:50000"),
				},
				Instance: "br1-ff00_0_110-1",
				LinkTo:   topology.Core,
				BFD: control.BFD{
					Disable:               ptr.To(false),
					DetectMult:            3,
					DesiredMinTxInterval:  200 * time.Millisecond,
					RequiredMinRxInterval: 300 * time.Millisecond,
				},
				MTU: 1472,
			},
			State: control.InterfaceUp,
		},
		{
			IfID: 2,
			Link: control.LinkInfo{
				Local: control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Addr: netip.MustParseAddrPort("172.20.0.3:50000"),
				},
				Remote: control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Addr: netip.MustParseAddrPort("172.20.0.2:50000"),
				},
				Instance: "br1-ff00_0_110-1",
				LinkTo:   topology.Child,
				BFD: control.BFD{
					Disable:               ptr.To(false),
					DetectMult:            3,
					DesiredMinTxInterval:  200 * time.Millisecond,
					RequiredMinRxInterval: 200 * time.Millisecond,
				},
				MTU: 1280,
			},
			State: control.InterfaceUp,
		},
		{
			IfID: 5,
			Link: control.LinkInfo{
				Local: control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:111"),
					Addr: netip.MustParseAddrPort("172.20.0.7:50000"),
				},
				Remote: control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:113"),
					Addr: netip.MustParseAddrPort("172.20.0.6:50000"),
				},
				Instance: "br1-ff00_0_111-1",
				LinkTo:   topology.Child,
				BFD: control.BFD{
					Disable:               ptr.To(false),
					DetectMult:            3,
					DesiredMinTxInterval:  150 * time.Millisecond,
					RequiredMinRxInterval: 150 * time.Millisecond,
				},
				MTU: 1280,
			},
			State: control.InterfaceUp,
		},
		{
			IfID: 6,
			Link: control.LinkInfo{
				Local: control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Addr: netip.MustParseAddrPort("172.20.0.78:50000"),
				},
				Remote: control.LinkEnd{
					IA:   addr.MustParseIA("1-ff00:0:113"),
					Addr: netip.MustParseAddrPort("172.20.0.10:50000"),
				},
				Instance: "br1-ff00_0_112-1",
				LinkTo:   topology.Child,
				BFD: control.BFD{
					Disable:               ptr.To(false),
					DetectMult:            3,
					DesiredMinTxInterval:  150 * time.Millisecond,
					RequiredMinRxInterval: 150 * time.Millisecond,
				},
				MTU: 1280,
			},
			State: control.InterfaceUp,
		},
	}
}

func createInternalIntfs(t *testing.T) []control.InternalInterface {
	return []control.InternalInterface{
		{
			IA:   addr.MustParseIA("1-ff00:0:110"),
			Addr: netip.MustParseAddrPort("172.20.0.3:50000"),
		},
		{
			IA:   addr.MustParseIA("1-ff00:0:111"),
			Addr: netip.MustParseAddrPort("172.20.0.5:50000"),
		},
	}
}

func createSiblingIntfs(t *testing.T) []control.SiblingInterface {
	return []control.SiblingInterface{
		{
			IfID:              5,
			InternalInterface: netip.MustParseAddrPort("172.20.0.20:30042"),
			Relationship:      topology.Parent,
			MTU:               1280,
			NeighborIA:        addr.MustParseIA("1-ff00:0:112"),
			State:             control.InterfaceUp,
		},
	}
}
