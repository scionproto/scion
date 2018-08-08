// Copyright 2018 ETH Zurich
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

package as_conf

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
)

func Test_MasterKeys(t *testing.T) {
	Convey("Loading test master keys `testdata/masterX.key`", t, func() {
		keys, err := LoadMasterKeys("testdata")
		if err != nil {
			t.Fatalf("Error loading config: %v", err)
		}
		SoMsg("Key0", keys.Key0, ShouldResemble,
			common.RawBytes("\xac\x93\x08{\xb5\x1c\x1d41\x9b\xd9u\xdd;\x88\xdc"))
		SoMsg("Key1", keys.Key1, ShouldResemble,
			common.RawBytes("X\x89\xff9\xa2\x12_#\x82-\xe8J4w\x0c*"))
	})
}
