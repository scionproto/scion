// Copyright 2016 ETH Zurich
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

	"github.com/scionproto/scion/go/lib/util"
)

func Test_ASConf(t *testing.T) {
	Convey("Loading test config `testdata/basic.yml`", t, func() {
		if err := Load("testdata/basic.yml"); err != nil {
			t.Fatalf("Error loading config: %v", err)
		}
		c := CurrConf
		So(c, ShouldResemble, &ASConf{
			1, util.B64Bytes("VV?=tJ\xae\x85s\r8\x9d\xfc\xe5\x94\xa5"), 21600, 5, true, 60,
		})
	})
}
