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

package trust_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/mock_trust"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

func TestInspectorByAttributes(t *testing.T) {
	tests := map[string]struct {
		Attrs       []infra.Attribute
		Expect      func(*mock_trust.MockCryptoProvider, *trc.TRC)
		ExpectedIAs []addr.IA
		ExpectedErr error
	}{
		"none": {
			Attrs:       []infra.Attribute{},
			Expect:      defaultExpect,
			ExpectedIAs: []addr.IA{ia110, ia120, ia130},
		},
		"core": {
			Attrs:       []infra.Attribute{infra.Core},
			Expect:      defaultExpect,
			ExpectedIAs: []addr.IA{ia110, ia130},
		},
		"issuing": {
			Attrs:       []infra.Attribute{infra.Issuing},
			Expect:      defaultExpect,
			ExpectedIAs: []addr.IA{ia120, ia130},
		},
		"voting": {
			Attrs:       []infra.Attribute{infra.Voting},
			Expect:      defaultExpect,
			ExpectedIAs: []addr.IA{ia130},
		},
		"error": {
			Expect: func(provider *mock_trust.MockCryptoProvider, _ *trc.TRC) {
				provider.EXPECT().GetTRC(gomock.Any(), trust.TRCID{ISD: trc1v1.ISD,
					Version: scrypto.LatestVer}, gomock.Any()).Return(nil, trust.ErrNotFound)
			},
			ExpectedErr: trust.ErrNotFound,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			// Setup the mocked objects.
			provider := mock_trust.NewMockCryptoProvider(mctrl)
			decoded := loadTRC(t, trc1v1)
			test.Expect(provider, decoded.TRC)
			ins := trust.DefaultInspector{
				Provider: provider,
			}
			// Prepare the request.
			opts := infra.ASInspectorOpts{
				RequiredAttributes: test.Attrs,
			}
			// Get by attributes.
			ias, err := ins.ByAttributes(context.Background(), trc1v1.ISD, opts)
			if test.ExpectedErr != nil {
				require.Error(t, err)
				require.Truef(t, errors.Is(err, test.ExpectedErr),
					"actual: %s\nexpected %s", err, test.ExpectedErr)
			} else {
				require.NoError(t, err)
				assert.ElementsMatch(t, test.ExpectedIAs, ias)
			}
		})
	}
}

func TestInspectorHasAttributes(t *testing.T) {
	tests := map[string]struct {
		IA          addr.IA
		Attrs       []infra.Attribute
		Expect      func(*mock_trust.MockCryptoProvider, *trc.TRC)
		Assertion   assert.BoolAssertionFunc
		ExpectedErr error
	}{
		"none": {
			IA:        ia110,
			Attrs:     []infra.Attribute{},
			Expect:    defaultExpect,
			Assertion: assert.True,
		},
		"core": {
			IA:        ia110,
			Attrs:     []infra.Attribute{infra.Core},
			Expect:    defaultExpect,
			Assertion: assert.True,
		},
		"authoritative": {
			IA:        ia110,
			Attrs:     []infra.Attribute{infra.Authoritative},
			Expect:    defaultExpect,
			Assertion: assert.True,
		},
		"core and authoritative": {
			IA:        ia110,
			Attrs:     []infra.Attribute{infra.Core, infra.Authoritative},
			Expect:    defaultExpect,
			Assertion: assert.True,
		},
		"core and voting": {
			IA:        ia110,
			Attrs:     []infra.Attribute{infra.Core, infra.Voting},
			Expect:    defaultExpect,
			Assertion: assert.False,
		},
		"non-primary": {
			IA:        ia122,
			Attrs:     []infra.Attribute{},
			Expect:    defaultExpect,
			Assertion: assert.False,
		},
		"error": {
			IA: ia110,
			Expect: func(provider *mock_trust.MockCryptoProvider, _ *trc.TRC) {
				provider.EXPECT().GetTRC(gomock.Any(), trust.TRCID{ISD: ia110.I,
					Version: scrypto.LatestVer}, gomock.Any()).Return(nil, trust.ErrNotFound)
			},
			ExpectedErr: trust.ErrNotFound,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			// Setup the mocked objects.
			provider := mock_trust.NewMockCryptoProvider(mctrl)
			decoded := loadTRC(t, trc1v1)
			test.Expect(provider, decoded.TRC)
			ins := trust.DefaultInspector{
				Provider: provider,
			}
			// Prepare the request.
			opts := infra.ASInspectorOpts{
				RequiredAttributes: test.Attrs,
			}
			// Check attribtues.
			has, err := ins.HasAttributes(context.Background(), test.IA, opts)
			if test.ExpectedErr != nil {
				require.Error(t, err)
				require.Truef(t, errors.Is(err, test.ExpectedErr),
					"actual: %s\nexpected %s", err, test.ExpectedErr)
			} else {
				require.NoError(t, err)
				test.Assertion(t, has)
			}
		})
	}
}

// defaultExpect modifies the returned TRC such that 1-ff00:0:110 is only
// authoritative and core, and 1-ff00:0:120 is issuing only.
func defaultExpect(provider *mock_trust.MockCryptoProvider, trcObj *trc.TRC) {
	entry := trcObj.PrimaryASes[ia110.A]
	entry.Attributes = []trc.Attribute{trc.Authoritative, trc.Core}
	trcObj.PrimaryASes[ia110.A] = entry
	entry = trcObj.PrimaryASes[ia120.A]
	entry.Attributes = []trc.Attribute{trc.Issuing}
	trcObj.PrimaryASes[ia120.A] = entry
	provider.EXPECT().GetTRC(gomock.Any(), trust.TRCID{ISD: addr.ISD(1),
		Version: scrypto.LatestVer}, gomock.Any()).Return(trcObj, nil)
}
