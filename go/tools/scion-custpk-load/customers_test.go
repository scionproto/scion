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

package main

import (
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb/mock_trustdb"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestLoadCustomers(t *testing.T) {
	key := common.RawBytes([]byte("aaaaaaa"))
	Convey("LoadCustomers", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		trustDB := mock_trustdb.NewMockTrustDB(ctrl)
		ia := xtest.MustParseIA("1-ff00:0:110")
		Convey("Given an empty DB: Load succeeds", func() {
			trustDB.EXPECT().GetCustKey(gomock.Any(), gomock.Eq(ia)).Return(nil, uint64(0), nil)
			trustDB.EXPECT().InsertCustKey(gomock.Any(), gomock.Eq(ia), uint64(1),
				gomock.Eq(key), uint64(0))
			files, loadedCusts, err := LoadCustomers("testdata/customers", trustDB)
			SoMsg("No err expected", err, ShouldBeNil)
			SoMsg("Exactly the file in test data expected", files, ShouldResemble,
				[]string{"testdata/customers/ISD1-ASff00_0_110-V1.key"})
			SoMsg("Correct cust meta expected", loadedCusts, ShouldResemble,
				[]*CustKeyMeta{{IA: xtest.MustParseIA("1-ff00:0:110"), Version: uint64(1)}})
		})
		Convey("Given a key with a newer version is stored: No changes done", func() {
			trustDB.EXPECT().GetCustKey(gomock.Any(), gomock.Eq(ia)).Return(nil, uint64(2), nil)
			files, loadedCusts, err := LoadCustomers("testdata/customers", trustDB)
			SoMsg("No err expected", err, ShouldBeNil)
			SoMsg("Exactly the file in test data expected", files, ShouldResemble,
				[]string{"testdata/customers/ISD1-ASff00_0_110-V1.key"})
			SoMsg("Loaded custs should be empty", loadedCusts, ShouldBeEmpty)
		})
	})
}
