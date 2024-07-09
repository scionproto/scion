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
	"net/netip"
	"strings"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
)

var (
	ParseAction         = parseAction
	ParseNetworkMatcher = parseNetworkMatcher
	ParseIAMatcher      = parseIAMatcher
	ParseRule           = parseRule
)

func NewIAMatcher(t *testing.T, ia string) IAMatcher {
	if strings.HasPrefix(ia, "!") {
		return NegatedIAMatcher{
			IAMatcher: SingleIAMatcher{
				IA: addr.MustParseIA(strings.TrimPrefix(ia, "!")),
			},
		}
	}
	return SingleIAMatcher{
		IA: addr.MustParseIA(ia),
	}
}

func NewNetworkMatcher(t *testing.T, networks string) NetworkMatcher {
	negated := strings.HasPrefix(networks, "!")
	if negated {
		networks = strings.TrimPrefix(networks, "!")
	}
	matcher := NetworkMatcher{Negated: negated}
	for _, network := range strings.Split(networks, ",") {
		matcher.Allowed = append(matcher.Allowed, netip.MustParsePrefix(network))
	}
	return matcher
}
