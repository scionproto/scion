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
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/xtest"
)

type validatorTest struct {
	Request        segfetcher.Request
	PrepareMock    func(i *mock_infra.MockASInspector)
	ErrorAssertion assert.ErrorAssertionFunc
}

var (
	ia110 = xtest.MustParseIA("1-ff00:0:110")
	ia111 = xtest.MustParseIA("1-ff00:0:111")
	ia120 = xtest.MustParseIA("1-ff00:0:120")
	isd1  = addr.IA{I: 1}
	isd2  = addr.IA{I: 2}
)

func TestBaseValidator(t *testing.T) {
	tests := map[string]validatorTest{
		"zero req": {
			Request:        segfetcher.Request{},
			PrepareMock:    func(i *mock_infra.MockASInspector) {},
			ErrorAssertion: assert.Error,
		},
		"non-core to wildcard": {
			Request: segfetcher.Request{Src: ia111, Dst: isd1},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia111, gomock.Any()).
					Return(false, nil)
			},
			ErrorAssertion: assert.NoError,
		},
		"non-core to non-local wildcard": {
			Request: segfetcher.Request{Src: ia111, Dst: isd2},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia111, gomock.Any()).
					Return(false, nil)
			},
			ErrorAssertion: assert.Error,
		},
		"non-core to core": {
			Request: segfetcher.Request{Src: ia111, Dst: ia120},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia111, gomock.Any()).
					Return(false, nil)
				i.EXPECT().HasAttributes(gomock.Any(), ia120, gomock.Any()).
					Return(true, nil)
			},
			ErrorAssertion: assert.NoError,
		},
	}
	addCommonTests(t, tests)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			i := mock_infra.NewMockASInspector(ctrl)
			test.PrepareMock(i)
			v := segreq.BaseValidator{CoreChecker: segreq.CoreChecker{Inspector: i}}
			test.ErrorAssertion(t, v.Validate(context.Background(), test.Request))
		})
	}
}

func TestCoreValidator(t *testing.T) {
	tests := map[string]validatorTest{
		"non-core to core": {
			Request: segfetcher.Request{Src: ia111, Dst: ia120},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia111, gomock.Any()).
					Return(false, nil).Times(2)
				i.EXPECT().HasAttributes(gomock.Any(), ia120, gomock.Any()).
					Return(true, nil)
			},
			ErrorAssertion: assert.Error,
		},
	}
	addCommonTests(t, tests)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			i := mock_infra.NewMockASInspector(ctrl)
			test.PrepareMock(i)
			v := segreq.CoreValidator{
				BaseValidator: segreq.BaseValidator{CoreChecker: segreq.CoreChecker{Inspector: i}},
			}
			test.ErrorAssertion(t, v.Validate(context.Background(), test.Request))
		})
	}
}

func addCommonTests(t *testing.T, tests map[string]validatorTest) {
	commonTests := map[string]validatorTest{
		"Core to core": {
			Request: segfetcher.Request{Src: ia110, Dst: ia120},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia110, gomock.Any()).
					Return(true, nil).MaxTimes(2)
				i.EXPECT().HasAttributes(gomock.Any(), ia120, gomock.Any()).
					Return(true, nil)
			},
			ErrorAssertion: assert.NoError,
		},
		"Wildcard to wildcard": {
			Request:        segfetcher.Request{Src: isd1, Dst: isd2},
			PrepareMock:    func(i *mock_infra.MockASInspector) {},
			ErrorAssertion: assert.Error,
		},
		"Wildcard to non-core": {
			Request: segfetcher.Request{Src: isd1, Dst: ia111},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia111, gomock.Any()).
					Return(false, nil).MaxTimes(2)
			},
			ErrorAssertion: assert.NoError,
		},
		"non-local wildcard to non-core": {
			Request: segfetcher.Request{Src: isd2, Dst: ia111},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia111, gomock.Any()).
					Return(false, nil).MaxTimes(2)
			},
			ErrorAssertion: assert.Error,
		},
		"core to non-core": {
			Request: segfetcher.Request{Src: ia120, Dst: ia111},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia111, gomock.Any()).
					Return(false, nil)
				i.EXPECT().HasAttributes(gomock.Any(), ia120, gomock.Any()).
					Return(true, nil).MaxTimes(2)
			},
			ErrorAssertion: assert.NoError,
		},
		"inspector error": {
			Request: segfetcher.Request{Src: ia111, Dst: ia120},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia111, gomock.Any()).
					Return(false, errors.New("Test error")).MaxTimes(2)
			},
			ErrorAssertion: assert.Error,
		},
	}
	for name, test := range commonTests {
		_, ok := tests[name]
		require.False(t, ok, "Double registration for test %s", name)
		tests[name] = test
	}
}
