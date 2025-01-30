// Copyright 2020 Anapaya Systems
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

package trust

import (
	"fmt"
	"net"

	"github.com/google/go-cmp/cmp"
)

type OptionsMatcher struct {
	AllowInactive bool
	Client        net.Addr
	Server        net.Addr
}

func (m OptionsMatcher) Matches(x any) bool {
	var o options

	if opts, ok := x.([]Option); ok {
		o = applyOptions(opts)
	} else if opt, ok := x.(Option); ok {
		opt(&o)
	} else {
		return false
	}

	return o.allowInactive == m.AllowInactive &&
		cmp.Equal(o.client, m.Client) &&
		cmp.Equal(o.server, m.Server)
}

func (m OptionsMatcher) String() string {
	type matcher OptionsMatcher
	return fmt.Sprintf("check applied options result in: %+v", matcher(m))
}
