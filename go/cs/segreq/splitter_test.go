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

func TestSplitter(t *testing.T) {
	ia110 := xtest.MustParseIA("1-ff00:0:110")
	ia120 := xtest.MustParseIA("1-ff00:0:120")
	ia111 := xtest.MustParseIA("1-ff00:0:111")
	ia112 := xtest.MustParseIA("1-ff00:0:112")
	isd1 := addr.IA{I: 1}

	tests := map[string]struct {
		Req            segfetcher.Request
		PrepareMock    func(i *mock_infra.MockASInspector)
		ErrorAssertion require.ErrorAssertionFunc
		ExpectedSet    segfetcher.RequestSet
	}{
		"Empty request": {
			Req:            segfetcher.Request{},
			PrepareMock:    func(i *mock_infra.MockASInspector) {},
			ErrorAssertion: require.Error,
			ExpectedSet:    segfetcher.RequestSet{},
		},
		"Non-core to core": {
			Req: segfetcher.Request{Src: ia111, Dst: isd1},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia111, gomock.Any()).Return(false, nil)
			},
			ErrorAssertion: require.NoError,
			ExpectedSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: ia111, Dst: isd1},
			},
		},
		"Core to non-core": {
			Req: segfetcher.Request{Src: ia120, Dst: ia111},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia111, gomock.Any()).Return(false, nil)
				i.EXPECT().HasAttributes(gomock.Any(), ia120, gomock.Any()).Return(true, nil)
			},
			ErrorAssertion: require.NoError,
			ExpectedSet: segfetcher.RequestSet{
				Down: segfetcher.Request{Src: ia120, Dst: ia111},
			},
		},
		"Core to core": {
			Req: segfetcher.Request{Src: ia110, Dst: ia120},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia110, gomock.Any()).Return(true, nil)
				i.EXPECT().HasAttributes(gomock.Any(), ia120, gomock.Any()).Return(true, nil)
			},
			ErrorAssertion: require.NoError,
			ExpectedSet: segfetcher.RequestSet{
				Cores: segfetcher.Requests{{Src: ia110, Dst: ia120}},
			},
		},
		"Non-core to non-core": {
			Req: segfetcher.Request{Src: ia111, Dst: ia112},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia111, gomock.Any()).Return(false, nil)
				i.EXPECT().HasAttributes(gomock.Any(), ia112, gomock.Any()).Return(false, nil)
			},
			ErrorAssertion: require.Error,
			ExpectedSet:    segfetcher.RequestSet{},
		},
		"Inspector error": {
			Req: segfetcher.Request{Src: ia110, Dst: ia120},
			PrepareMock: func(i *mock_infra.MockASInspector) {
				i.EXPECT().HasAttributes(gomock.Any(), ia110, gomock.Any()).Return(true, nil)
				i.EXPECT().HasAttributes(gomock.Any(), ia120, gomock.Any()).
					Return(false, errors.New("test error"))
			},
			ErrorAssertion: require.Error,
			ExpectedSet:    segfetcher.RequestSet{},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			i := mock_infra.NewMockASInspector(ctrl)
			test.PrepareMock(i)
			splitter := segreq.Splitter{ASInspector: i}
			rs, err := splitter.Split(context.Background(), test.Req)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedSet, rs)
		})
	}
}
