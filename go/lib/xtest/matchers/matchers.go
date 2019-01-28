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

// File matchers contains matchers for gomock.

package matchers

import (
	"fmt"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ gomock.Matcher = (*addrIAMatcher)(nil)

type addrIAMatcher struct {
	ia addr.IA
}

// IsSnetAddrWithIA returns a matcher for a snet.Addr with the given IA.
func IsSnetAddrWithIA(ia addr.IA) gomock.Matcher {
	return &addrIAMatcher{ia: ia}
}

func (m *addrIAMatcher) Matches(x interface{}) bool {
	sAddr, ok := x.(*snet.Addr)
	if !ok {
		return false
	}
	return sAddr.IA.Equal(m.ia)
}

func (m *addrIAMatcher) String() string {
	return fmt.Sprintf("Matching addr with IA %v", m.ia)
}
