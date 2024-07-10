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
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/control/mock_control"
	"github.com/scionproto/scion/gateway/routing"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
)

func TestPrefixesFilterPrefixes(t *testing.T) {
	type input struct {
		IA       addr.IA
		Gateway  control.Gateway
		Prefixes []*net.IPNet
	}
	testCases := map[string]struct {
		CreateFilter func(*testing.T, *gomock.Controller) control.PrefixesFilter
		Inputs       []input
	}{
		"nil policy filters all": {
			CreateFilter: func(_ *testing.T, ctrl *gomock.Controller) control.PrefixesFilter {
				consumer := mock_control.NewMockPrefixConsumer(ctrl)
				provider := mock_control.NewMockRoutingPolicyProvider(ctrl)
				provider.EXPECT().RoutingPolicy().Times(2)
				f := control.PrefixesFilter{
					LocalIA:        addr.MustParseIA("1-ff00:0:110"),
					PolicyProvider: provider,
					Consumer:       consumer,
				}
				return f
			},
			Inputs: []input{
				{
					IA:       addr.MustParseIA("1-ff00:0:111"),
					Gateway:  control.Gateway{},
					Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/25"),
				},
				{
					IA:       addr.MustParseIA("1-ff00:0:112"),
					Gateway:  control.Gateway{},
					Prefixes: xtest.MustParseCIDRs(t, "10.4.0.0/25"),
				},
			},
		},
		"deny all filters all": {
			CreateFilter: func(_ *testing.T, ctrl *gomock.Controller) control.PrefixesFilter {
				consumer := mock_control.NewMockPrefixConsumer(ctrl)
				consumer.EXPECT().Prefixes(addr.MustParseIA("1-ff00:0:111"),
					gomock.Any(), nil).Return(nil)
				consumer.EXPECT().Prefixes(addr.MustParseIA("1-ff00:0:112"),
					gomock.Any(), nil).Return(nil)
				provider := mock_control.NewMockRoutingPolicyProvider(ctrl)
				provider.EXPECT().RoutingPolicy().
					Return(&routing.Policy{DefaultAction: routing.Reject}).Times(2)
				f := control.PrefixesFilter{
					LocalIA:        addr.MustParseIA("1-ff00:0:110"),
					PolicyProvider: provider,
					Consumer:       consumer,
				}
				return f
			},
			Inputs: []input{
				{
					IA:       addr.MustParseIA("1-ff00:0:111"),
					Gateway:  control.Gateway{},
					Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/25"),
				},
				{
					IA:       addr.MustParseIA("1-ff00:0:112"),
					Gateway:  control.Gateway{},
					Prefixes: xtest.MustParseCIDRs(t, "10.4.0.0/25"),
				},
			},
		},
		"allow all filters none": {
			CreateFilter: func(_ *testing.T, ctrl *gomock.Controller) control.PrefixesFilter {
				consumer := mock_control.NewMockPrefixConsumer(ctrl)
				consumer.EXPECT().Prefixes(addr.MustParseIA("1-ff00:0:111"),
					gomock.Any(), xtest.MustParseCIDRs(t, "10.1.0.0/25")).Return(nil)
				consumer.EXPECT().Prefixes(addr.MustParseIA("1-ff00:0:112"),
					gomock.Any(), xtest.MustParseCIDRs(t, "10.4.0.0/25")).Return(nil)
				provider := mock_control.NewMockRoutingPolicyProvider(ctrl)
				provider.EXPECT().RoutingPolicy().
					Return(&routing.Policy{DefaultAction: routing.Accept}).Times(2)
				f := control.PrefixesFilter{
					LocalIA:        addr.MustParseIA("1-ff00:0:110"),
					PolicyProvider: provider,
					Consumer:       consumer,
				}
				return f
			},
			Inputs: []input{
				{
					IA:       addr.MustParseIA("1-ff00:0:111"),
					Gateway:  control.Gateway{},
					Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/25"),
				},
				{
					IA:       addr.MustParseIA("1-ff00:0:112"),
					Gateway:  control.Gateway{},
					Prefixes: xtest.MustParseCIDRs(t, "10.4.0.0/25"),
				},
			},
		},
		"routing policy filters correctly": {
			CreateFilter: func(t *testing.T, ctrl *gomock.Controller) control.PrefixesFilter {
				consumer := mock_control.NewMockPrefixConsumer(ctrl)
				consumer.EXPECT().Prefixes(addr.MustParseIA("1-ff00:0:111"),
					gomock.Any(), xtest.MustParseCIDRs(t, "10.1.0.0/25")).Return(nil)
				consumer.EXPECT().Prefixes(addr.MustParseIA("1-ff00:0:112"),
					gomock.Any(), xtest.MustParseCIDRs(t, "10.4.0.0/25")).Return(nil)
				consumer.EXPECT().Prefixes(addr.MustParseIA("1-ff00:0:113"),
					gomock.Any(), nil).Return(nil)
				pol := &routing.Policy{DefaultAction: routing.Reject}
				err := pol.UnmarshalText(
					[]byte(`accept    1-ff00:0:111    1-ff00:0:110    10.1.0.0/25
accept    1-ff00:0:112    1-ff00:0:110    10.4.0.0/25
accept    1-ff00:0:113    1-ff00:0:110    10.3.0.0/25`))
				require.NoError(t, err)
				provider := mock_control.NewMockRoutingPolicyProvider(ctrl)
				provider.EXPECT().RoutingPolicy().
					Return(pol).Times(3)
				f := control.PrefixesFilter{
					LocalIA:        addr.MustParseIA("1-ff00:0:110"),
					PolicyProvider: provider,
					Consumer:       consumer,
				}
				return f
			},
			Inputs: []input{
				{
					IA:       addr.MustParseIA("1-ff00:0:111"),
					Gateway:  control.Gateway{},
					Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/25", "127.0.0.0/8", "172.0.0.0/8"),
				},
				{
					IA:       addr.MustParseIA("1-ff00:0:112"),
					Gateway:  control.Gateway{},
					Prefixes: xtest.MustParseCIDRs(t, "10.4.0.0/25", "127.0.0.0/8", "172.0.0.0/8"),
				},
				{
					IA:       addr.MustParseIA("1-ff00:0:113"),
					Gateway:  control.Gateway{},
					Prefixes: xtest.MustParseCIDRs(t, "127.0.0.0/8", "172.0.0.0/8"),
				},
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			f := tc.CreateFilter(t, ctrl)
			for _, input := range tc.Inputs {
				err := f.Prefixes(input.IA, input.Gateway, input.Prefixes)
				require.NoError(t, err)
			}
		})
	}
}
