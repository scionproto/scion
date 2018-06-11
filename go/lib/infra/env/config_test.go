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

package env

import (
	"fmt"
	"io/ioutil"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestLoadBase(t *testing.T) {
	Convey("Load", t, func() {
		var cfg Config
		err := LoadConfig(ioutil.Discard, "testdata/sciond.toml", &cfg)
		SoMsg("err", err, ShouldBeNil)
		fmt.Printf("%+v\n", cfg)
	})
}

func TestLoadDerived(t *testing.T) {
	Convey("Load", t, func() {
		var cfg struct {
			Config
			Extra int
		}
		err := LoadConfig(ioutil.Discard, "testdata/sciond.toml", &cfg)
		SoMsg("err", err, ShouldBeNil)
		fmt.Printf("%+v\n", cfg)
	})
}
