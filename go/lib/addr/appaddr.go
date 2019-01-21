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

package addr

import (
	"fmt"
)

type AppAddr struct {
	L3 HostAddr
	L4 L4Info
}

func (a *AppAddr) Copy() *AppAddr {
	return &AppAddr{L3: a.L3.Copy(), L4: a.L4.Copy()}
}

func (a *AppAddr) Equal(o *AppAddr) bool {
	if (a == nil) || (o == nil) {
		return a == o
	}
	return a.L3.Equal(o.L3) && a.L4.Equal(o.L4)
}

func (a *AppAddr) EqType(o *AppAddr) bool {
	if (a == nil) || (o == nil) {
		return a == o
	}
	return a.L3.Type() == o.L3.Type() && a.L4.Type() == o.L4.Type()
}

func (a *AppAddr) Network() string {
	// FIXME implement proper network
	// Should we report Go style, ie. udp4, udp6, etc.
	return "AppAddr"
}

func (a *AppAddr) String() string {
	if a.L4 != nil {
		return fmt.Sprintf("[%v]:%d", a.L3, a.L4.Port())
	}
	return fmt.Sprintf("[%v]", a.L3)
}
