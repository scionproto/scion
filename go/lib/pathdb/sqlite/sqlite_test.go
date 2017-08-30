// Copyright 2017 ETH Zurich
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

package sqlite

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	testDBPrefix = "/tmp/"
)


func Test_InsertWithLabelFull(t *testing.T) {
	Convey("InsertWithLabel should correctly insert a new segment", t, func() {
		// TODO(shitz): use tmp file.
		db, _ := New("/tmp/foo")

	})
}