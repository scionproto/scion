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

package routing

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
)

// singleIAMatcher matches other ISD-AS numbers based on a single ISD-AS.
type SingleIAMatcher struct {
	IA addr.IA
}

// Match matches the input ISD-AS if both the ISD and the AS number are the same
// as the one of the matcher. Zero values of ISD and AS in the matchers ISD-AS
// are treated as wildcards and match everything.
func (m SingleIAMatcher) Match(ia addr.IA) bool {
	switch {
	case m.IA.IsZero():
		return true
	case m.IA.ISD() == 0:
		return m.IA.AS() == ia.AS()
	case m.IA.AS() == 0:
		return m.IA.ISD() == ia.ISD()
	default:
		return m.IA.Equal(ia)
	}
}

func (m SingleIAMatcher) String() string {
	return m.IA.String()
}

// negatedIAMatcher negates the result of the enclosed matcher.
type NegatedIAMatcher struct {
	IAMatcher
}

// Match negates the result of the enclosed matcher.
func (m NegatedIAMatcher) Match(ia addr.IA) bool {
	return !m.IAMatcher.Match(ia)
}

func (m NegatedIAMatcher) String() string {
	return fmt.Sprintf("!%s", m.IAMatcher)
}
