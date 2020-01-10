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

package segreq_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/segreq"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestCoreChecker(t *testing.T) {
	tests := map[string]struct {
		IA               addr.IA
		PrepareInspector func(i *mock_infra.MockASInspector)
		ErrorAssertion   require.ErrorAssertionFunc
		ExpectedCore     bool
	}{
		"Wildcard": {
			IA:               xtest.MustParseIA("1-0"),
			PrepareInspector: func(i *mock_infra.MockASInspector) {},
			ErrorAssertion:   require.NoError,
			ExpectedCore:     true,
		},
		"InspectorError": {
			IA: xtest.MustParseIA("1-ff00:0:110"),
			PrepareInspector: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(false, errors.New("test error"))
			},
			ErrorAssertion: require.Error,
			ExpectedCore:   false,
		},
		"Core": {
			IA: xtest.MustParseIA("1-ff00:0:110"),
			PrepareInspector: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(true, nil)
			},
			ErrorAssertion: require.NoError,
			ExpectedCore:   true,
		},
		"Non-Core": {
			IA: xtest.MustParseIA("1-ff00:0:110"),
			PrepareInspector: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(false, nil)
			},
			ErrorAssertion: require.NoError,
			ExpectedCore:   false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			i := mock_infra.NewMockASInspector(ctrl)
			test.PrepareInspector(i)
			c := segreq.CoreChecker{Inspector: i}
			core, err := c.IsCore(context.Background(), test.IA)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedCore, core)
		})
	}
}
