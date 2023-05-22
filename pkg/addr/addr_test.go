// Copyright 2023 SCION Association
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

package addr_test

import (
	"fmt"

	"github.com/scionproto/scion/pkg/addr"
)

func ExampleParseAddr() {
	a, err := addr.ParseAddr("6-ffaa:0:123,198.51.100.1")
	fmt.Printf("a: %+v, err: %v\n", a, err)
}
