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
	"strings"
	"testing"

	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	IsSubnet            = isSubnet
	ParseAction         = parseAction
	ParseNetworkMatcher = parseNetworkMatcher
	ParseIAMatcher      = parseIAMatcher
	ParseRule           = parseRule
)

type SingleIAMatcher = singleIAMatcher

func NewIAMatcher(t *testing.T, ia string) IAMatcher {
	if strings.HasPrefix(ia, "!") {
		return negatedIAMatcher{
			IAMatcher: singleIAMatcher{
				IA: xtest.MustParseIA(strings.TrimPrefix(ia, "!")),
			},
		}
	}
	return singleIAMatcher{
		IA: xtest.MustParseIA(ia),
	}
}

func NewNetworkMatcher(t *testing.T, networks string) NetworkMatcher {
	negated := strings.HasPrefix(networks, "!")
	if negated {
		networks = strings.TrimPrefix(networks, "!")
	}
	matcher := allowedNetworkMatcher{}
	for _, network := range strings.Split(networks, ",") {
		matcher.Allowed = append(matcher.Allowed, xtest.MustParseCIDR(t, network))
	}
	if negated {
		return negatedNetworkMatcher{NetworkMatcher: matcher}
	}
	return matcher
}
