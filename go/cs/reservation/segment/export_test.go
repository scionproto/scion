// Copyright 2020 ETH Zurich, Anapaya Systems
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

package segment

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest"
)

func newPathFromComponents(chain ...interface{}) Path {
	if len(chain)%3 != 0 {
		panic("wrong number of arguments")
	}
	p := Path{}
	for i := 0; i < len(chain); i += 3 {
		p = append(p, PathStep{
			Ingress: common.IFIDType(chain[i].(int)),
			AS:      xtest.MustParseAS(chain[i+1].(string)),
			Egress:  common.IFIDType(chain[i+2].(int)),
		})
	}
	return p
}
