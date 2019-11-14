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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/mock_v2"
)

func TestInserterInsertTRC(t *testing.T) {
	tests := map[string]struct {
		Expect      func(*mock_v2.MockDB, decoded.TRC)
		Unsafe      bool
		ExpectedErr error
	}{
		"Exists with same contents": {
			Expect: func(db *mock_v2.MockDB, decTRC decoded.TRC) {
				db.EXPECT().TRCExists(gomock.Any(), decTRC).Return(
					true, nil,
				)
			},
		},
		"Exists with different contents": {
			Expect: func(db *mock_v2.MockDB, decTRC decoded.TRC) {
				db.EXPECT().TRCExists(gomock.Any(), decTRC).Return(
					true, trust.ErrContentMismatch,
				)
			},
			ExpectedErr: trust.ErrContentMismatch,
		},
		"Base TRC and unsafe set": {
			Expect: func(db *mock_v2.MockDB, decTRC decoded.TRC) {
				db.EXPECT().TRCExists(gomock.Any(), decTRC).Return(
					false, nil,
				)
				db.EXPECT().InsertTRC(gomock.Any(), decTRC).Return(true, nil)
			},
			Unsafe: true,
		},
		"Base TRC and unsafe set, insert fail": {
			Expect: func(db *mock_v2.MockDB, decTRC decoded.TRC) {
				db.EXPECT().TRCExists(gomock.Any(), decTRC).Return(
					false, nil,
				)
				db.EXPECT().InsertTRC(gomock.Any(), decTRC).Return(
					false, trust.ErrContentMismatch,
				)
			},
			ExpectedErr: trust.ErrContentMismatch,
			Unsafe:      true,
		},
		"Base TRC and unsafe not set": {
			Expect: func(db *mock_v2.MockDB, decTRC decoded.TRC) {
				db.EXPECT().TRCExists(gomock.Any(), decTRC).Return(
					false, nil,
				)
			},
			ExpectedErr: trust.ErrBaseNotSupported,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			db := mock_v2.NewMockDB(mctrl)
			decoded := loadTRC(t, trc1v1)
			test.Expect(db, decoded)
			ins := trust.NewInserter(db, test.Unsafe)

			err := ins.InsertTRC(context.Background(), decoded, nil)
			if test.ExpectedErr != nil {
				require.Truef(t, xerrors.Is(err, test.ExpectedErr),
					"Expected: %s Actual: %s", test.ExpectedErr, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
