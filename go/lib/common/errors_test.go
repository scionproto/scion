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

package common

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_FmtError(t *testing.T) {
	var err error = NewBasicError(
		"level0\nlevel0.1",
		fmt.Errorf("level1\nlevel1.1"),
		"k0", "v0", "k1", 1,
	)
	Convey("FmtError formats correctly", t, func() {
		So(FmtError(err), ShouldEqual, `level0
    >   level0.1 k0="v0" k1="1"
    level1
    >   level1.1`)
	})
}
