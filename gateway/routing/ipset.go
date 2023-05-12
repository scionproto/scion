// Copyright 2022 Anapaya Systems
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

	"go4.org/netipx"
)

// IPSet is the same as netipx.IPSet except that it can be converted to/from string.
type IPSet struct {
	netipx.IPSet
}

func ParseIPSet(s string) (IPSet, error) {
	var sb netipx.IPSetBuilder
	prefixes := strings.Split(s, ",")
	for _, prefix := range prefixes {
		if prefix == "" {
			continue
		}
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			return IPSet{}, err
		}
		sb.AddPrefix(p)
	}
	set, err := sb.IPSet()
	if err != nil {
		return IPSet{}, err
	}
	return IPSet{IPSet: *set}, nil
}

func MustParseIPSet(s string) IPSet {
	set, err := ParseIPSet(s)
	if err != nil {
		panic(err)
	}
	return set
}

func (s *IPSet) String() string {
	var prefixes []string
	for _, prefix := range s.Prefixes() {
		prefixes = append(prefixes, prefix.String())
	}
	return strings.Join(prefixes, ",")
}
